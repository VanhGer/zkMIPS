package zkm

import (
//     "bufio"
	"encoding/json"
	"fmt"
	"os"
//     "encoding/binary"
    "log"
//     "io"
// 	"github.com/consensys/gnark-crypto/ecc"
// 	"github.com/consensys/gnark/backend/groth16"
    fr "github.com/consensys/gnark-crypto/ecc/sect/fr"
    bcs "github.com/consensys/gnark/constraint/sect"
    "github.com/consensys/gnark/frontend/cs/r1cs"
// 	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
// 	"github.com/consensys/gnark/backend/witness"

)

func DumpGroth16(witnessInputPath string, dumpWitnessPath string, circuitInputPath string, dumpCircuitPath string) {
    data, err := os.ReadFile(witnessInputPath)
    if err != nil {
        panic(err)
    }

    // Deserialize the JSON data into a slice of Instruction structs
    var witnessInput WitnessInput
    err = json.Unmarshal(data, &witnessInput)
    if err != nil {
        panic(err)
    }


    // Initialize the circuit.
	circuit := NewCircuit(witnessInput)

	// Compile the circuit.
	r1cs, err := frontend.Compile(fr.Modulus(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}
    r1csFile, err := os.Open(dumpCircuitPath)
    if err != nil {
        panic(err)
    }
    r1cs_contr := r1cs.(*bcs.R1CS)
    Dump(r1cs_contr, r1csFile)

    assignment := NewCircuit(witnessInput)
    witness, err2 := frontend.NewWitness(&assignment, fr.Modulus())
    if err2 != nil {
        panic(err2)
    }

    vector, ok := witness.Vector().(fr.Vector)
    if ok {
        fmt.Printf("Witness length: %d\n", len(vector))
    } else {
        fmt.Println("Witness vector type assertion failed")
    }

    publicWitnessData, err := witness.Public()
    fmt.Printf("public length: %d\n", len(publicWitnessData.Vector().(fr.Vector)))

    // Check if the witness satisfies the circuit
    _solution, _ := r1cs.Solve(witness)

    // concrete solution
   	solution := _solution.(*bcs.R1CSSolution)

    fmt.Printf("W length: %d\n", len(solution.W))
    if len(solution.W) > 0 {
        fmt.Printf("W[0]: %s\n", solution.W[0].String())
    }

    wfile, err3 := os.Create(dumpWitnessPath)
    if err3 != nil {
        panic(err3)
    }
    defer wfile.Close()

    bytesWritten, err := solution.W.WriteTo(wfile)
    if err != nil {
        log.Fatalf("Failed to write to file: %v", err)
    }

	fmt.Printf("Successfully wrote %d bytes to %s\n", bytesWritten, dumpWitnessPath)

}
