package verifier

import (
	"fmt"
	"log"
	"math"
	"time"

	"github.com/alitto/pond"
	"github.com/consensys/gnark-crypto/ecc/bn254"
)

type Config struct {
	G1Path    string
	G2Path    string
	NumPoint  uint64
	NumBatch  uint64
	NumWorker int
}

const numUpdate = 20

func VerifySRS(config Config) {
	numPoint := config.NumPoint
	numBatch := config.NumBatch

	batchSize := uint64(math.Ceil(float64(numPoint) / float64(numBatch)))

	processStart := time.Now()

	updateSize := int64(numBatch / numUpdate)

	fmt.Println("In total, will verify", numBatch, "batches")

	for i := int64(0); i < int64(numBatch); i++ {
		begin := time.Now()
		from := i*int64(batchSize) - 1
		to := (i + 1) * int64(batchSize)
		if from < 0 {
			from = 0
		}
		if uint64(to) > numPoint {
			to = int64(numPoint)
		}

		g1points, err := ReadG1PointSection(config.G1Path, uint64(from), uint64(to), 8)
		if err != nil {
			fmt.Println("err", err)
			return
		}

		g2points, err := ReadG2PointSection(config.G2Path, uint64(from), uint64(to), 8)
		if err != nil {
			fmt.Println("err", err)
			return
		}
		pool := pond.New(8, 0, pond.MinWorkers(8))
		verifyBegin := time.Now()
		G1Check(g1points, g2points, pool)
		G2Check(g1points, g2points, pool)

		// Stop the pool and wait for all submitted tasks to complete
		pool.StopAndWait()

		if i == 0 {
			elapsed := time.Since(begin)
			expectedFinishDuration := uint64(elapsed.Seconds()) * numBatch
			fmt.Printf("verify 1 batch takes %v. Verify takes %v\n", elapsed, time.Since(verifyBegin))
			fmt.Printf("verify %v batches will take %v Hours\n", numBatch, expectedFinishDuration/3600.0)
			fmt.Printf("Showing updates every %v batches\n", updateSize)
		} else if i%updateSize == 0 {
			fmt.Printf("Verified %v-th batches. Time spent so far is %v\n", i, time.Since(processStart))
		}
	}

	fmt.Println("Done. Everything is correct")
}

// https://github.com/ethereum/kzg-ceremony-specs/blob/master/docs/sequencer/sequencer.md#pairing-checks
func G1Check(g1points []bn254.G1Affine, g2points []bn254.G2Affine, pool *pond.WorkerPool) {
	n := uint64(len(g1points))
	if len(g1points) != len(g2points) {
		panic("not equal length")
	}

	for i := uint64(0); i < n-1; i++ {
		z := i
		pool.Submit(func() {
			var negB1 bn254.G1Affine
			negB1.Neg((*bn254.G1Affine)(&g1points[z]))

			P := [2]bn254.G1Affine{*(*bn254.G1Affine)(&g1points[z+1]), negB1}
			Q := [2]bn254.G2Affine{*(*bn254.G2Affine)(&g2points[0]), *(*bn254.G2Affine)(&g2points[1])}

			_, err := bn254.PairingCheck(P[:], Q[:])
			if err != nil {
				log.Fatalf("pairing failed %v\n", err)
				panic("error")
			}
		})
	}
}

// https://github.com/ethereum/kzg-ceremony-specs/blob/master/docs/sequencer/sequencer.md#pairing-checks
func G2Check(g1points []bn254.G1Affine, g2points []bn254.G2Affine, pool *pond.WorkerPool) {
	n := uint64(len(g1points))
	if len(g1points) != len(g2points) {
		panic("not equal length")
	}

	for i := uint64(0); i < n; i++ {
		z := i
		pool.Submit(func() {
			var negB1 bn254.G1Affine
			negB1.Neg((*bn254.G1Affine)(&g1points[0]))

			P := [2]bn254.G1Affine{*(*bn254.G1Affine)(&g1points[z]), negB1}
			Q := [2]bn254.G2Affine{*(*bn254.G2Affine)(&g2points[0]), *(*bn254.G2Affine)(&g2points[z])}

			_, err := bn254.PairingCheck(P[:], Q[:])
			if err != nil {
				log.Fatalf("pairing failed %v\n", err)
			}
		})
	}
}
