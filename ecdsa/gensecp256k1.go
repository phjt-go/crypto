// +build gensecp256k1

package ecdsa

// 引用:
//   [GECC]:椭圆曲线密码学指南(Hankerson, Menezes, Vanstone)

import (
	"encoding/binary"
	"math/big"
)

// getDoublingPoints 返回所有可能的 G^(2^i)循环在0..n-1 其中n是曲线的位大小(256 in the case of secp256k1) 坐标记录为雅可比矩阵坐标。
func (curve *KoblitzCurve) getDoublingPoints() [][3]fieldVal {
	doublingPoints := make([][3]fieldVal, curve.BitSize)

	// 将px py pz初始化为基点的雅可比矩阵坐标
	px, py := curve.bigAffineToField(curve.Gx, curve.Gy)
	pz := new(fieldVal).SetInt(1)
	for i := 0; i < curve.BitSize; i++ {
		doublingPoints[i] = [3]fieldVal{*px, *py, *pz}
		// P = 2*P
		curve.doubleJacobian(px, py, pz, px, py, pz)
	}
	return doublingPoints
}

//序列化bytepoints返回一个序列化的[]byte数组，其中包含所有每个8位bit 的所有可能点。这用于生成secp256k1.go
func (curve *KoblitzCurve) SerializedBytePoints() []byte {
	doublingPoints := curve.getDoublingPoints()

	// Segregate the bits into byte-sized windows
	serialized := make([]byte, curve.byteSize*256*3*10*4)
	offset := 0
	for byteNum := 0; byteNum < curve.byteSize; byteNum++ {
		// Grab the 8 bits that make up this byte from doublingPoints.
		startingBit := 8 * (curve.byteSize - byteNum - 1)
		computingPoints := doublingPoints[startingBit : startingBit+8]

		// 计算系统中所有节点并序列化它们
		for i := 0; i < 256; i++ {
			px, py, pz := new(fieldVal), new(fieldVal), new(fieldVal)
			for j := 0; j < 8; j++ {
				if i>>uint(j)&1 == 1 {
					curve.addJacobian(px, py, pz, &computingPoints[j][0],
						&computingPoints[j][1], &computingPoints[j][2], px, py, pz)
				}
			}
			for i := 0; i < 10; i++ {
				binary.LittleEndian.PutUint32(serialized[offset:], px.n[i])
				offset += 4
			}
			for i := 0; i < 10; i++ {
				binary.LittleEndian.PutUint32(serialized[offset:], py.n[i])
				offset += 4
			}
			for i := 0; i < 10; i++ {
				binary.LittleEndian.PutUint32(serialized[offset:], pz.n[i])
				offset += 4
			}
		}
	}

	return serialized
}

// 使用牛顿方法，根号返回提供的大整数的平方根。它只在生成预计算值时进行编译和使用，所以速度不是一个大问题。
func sqrt(n *big.Int) *big.Int {
	// Initial guess = 2^(log_2(n)/2)
	guess := big.NewInt(2)
	guess.Exp(guess, big.NewInt(int64(n.BitLen()/2)), nil)

	// Now refine using Newton's method.
	big2 := big.NewInt(2)
	prevGuess := big.NewInt(0)
	for {
		prevGuess.Set(guess)
		guess.Add(guess, new(big.Int).Div(n, guess))
		guess.Div(guess, big2)
		if guess.Cmp(prevGuess) == 0 {
			break
		}
	}
	return guess
}

//EndomorphismVectors运行算法3.74的前3步(GECC)来生成所需的线性无关的向量生成一个平衡乘数的长度表示,k = k1 + k2λ(mod N)并返回它们。
// 因为值总是相同的考虑到N和λ是固定的,最终结果可以通过存储预先计算的加速值曲线。
func (curve *KoblitzCurve) EndomorphismVectors() (a1, b1, a2, b2 *big.Int) {
	bigMinus1 := big.NewInt(-1)

	// This section uses an extended Euclidean algorithm to generate a sequence of equations:
	// 本节使用扩展欧几里得算法生成一系列方程
	//  s[i] * N + t[i] * λ = r[i]

	nSqrt := sqrt(curve.N)
	u, v := new(big.Int).Set(curve.N), new(big.Int).Set(curve.lambda)
	x1, y1 := big.NewInt(1), big.NewInt(0)
	x2, y2 := big.NewInt(0), big.NewInt(1)
	q, r := new(big.Int), new(big.Int)
	qu, qx1, qy1 := new(big.Int), new(big.Int), new(big.Int)
	s, t := new(big.Int), new(big.Int)
	ri, ti := new(big.Int), new(big.Int)
	a1, b1, a2, b2 = new(big.Int), new(big.Int), new(big.Int), new(big.Int)
	found, oneMore := false, false
	for u.Sign() != 0 {
		// q = v/u
		q.Div(v, u)

		// r = v - q*u
		qu.Mul(q, u)
		r.Sub(v, qu)

		// s = x2 - q*x1
		qx1.Mul(q, x1)
		s.Sub(x2, qx1)

		// t = y2 - q*y1
		qy1.Mul(q, y1)
		t.Sub(y2, qy1)

		// v = u, u = r, x2 = x1, x1 = s, y2 = y1, y1 = t
		v.Set(u)
		u.Set(r)
		x2.Set(x1)
		x1.Set(s)
		y2.Set(y1)
		y1.Set(t)

		// 只要余数小于根号n, a1和b1的值就已知了。
		if !found && r.Cmp(nSqrt) < 0 {
			// 当这个条件执行ri时，ti表示r[i]和t[i]的值，使得i是r >= sqrt(n)的最大索引。同时，当前的r和t值分别为r[i+1]和t[i+1]。

			// a1 = r[i+1], b1 = -t[i+1]
			a1.Set(r)
			b1.Mul(t, bigMinus1)
			found = true
			oneMore = true

			// 跳到下一个迭代，这样ri和ti就不会被修改。
			continue

		} else if oneMore {
			// 当这个条件执行时，ri和ti仍然表示r[i]和t[i]的值，而当前r和t分别为r[i+2]和t[i+2]。

			// sum1 = r[i]^2 + t[i]^2
			rSquared := new(big.Int).Mul(ri, ri)
			tSquared := new(big.Int).Mul(ti, ti)
			sum1 := new(big.Int).Add(rSquared, tSquared)

			// sum2 = r[i+2]^2 + t[i+2]^2
			r2Squared := new(big.Int).Mul(r, r)
			t2Squared := new(big.Int).Mul(t, t)
			sum2 := new(big.Int).Add(r2Squared, t2Squared)

			// if (r[i]^2 + t[i]^2) <= (r[i+2]^2 + t[i+2]^2)
			if sum1.Cmp(sum2) <= 0 {
				// a2 = r[i], b2 = -t[i]
				a2.Set(ri)
				b2.Mul(ti, bigMinus1)
			} else {
				// a2 = r[i+2], b2 = -t[i+2]
				a2.Set(r)
				b2.Mul(t, bigMinus1)
			}

			// All done.
			break
		}

		ri.Set(r)
		ti.Set(t)
	}

	return a1, b1, a2, b2
}
