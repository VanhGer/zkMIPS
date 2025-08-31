package zkm

import (
    "bufio"
	"encoding/json"
	"fmt"
	"os"
    "encoding/binary"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
    cs "github.com/consensys/gnark/constraint/bn254"
    "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/backend/witness"

)

func DumpGroth16Witness(witnessInputPath string, dumpWitnessPath string) {
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

    assignment := NewCircuit(witnessInput)
    witness, err2 := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
    if err2 != nil {
        panic(err2)
    }
    err3 := DumpWitness(witness, dumpWitnessPath)
    if err3 != nil {
        panic(err3)
    }
}

func DumpWitness(w witness.Witness, filePath string) error {
    f, err := os.Create(filePath)
    if err != nil {
        return err
    }
    defer f.Close()

    vector, ok := w.Vector().(fr.Vector)
    if !ok {
        return fmt.Errorf("unexpected witness vector type")
    }
    for _, el := range vector {
        b := el.Bytes() // [32]byte, big-endian
        if _, err := f.Write(b[:]); err != nil {
            return err
        }
    }
    return nil
}

func DumpGroth16Circuit(circuitInputPath string, dumpCircuitPath string) {
    var r1cs constraint.ConstraintSystem = groth16.NewCS(ecc.BN254)
    r1csFile, err := os.Open(circuitInputPath)
    if err != nil {
        panic(err)
    }
    r1csReader := bufio.NewReaderSize(r1csFile, 1024*1024)
    r1cs.ReadFrom(r1csReader)
    defer r1csFile.Close()

//     fmt.Println(r1cs)
    err2 := DumpR1CS(r1cs.(*cs.R1CS), dumpCircuitPath)
    if err2 != nil {
        panic(err2)
    }
}

func DumpR1CS(r1cs *cs.R1CS, filePath string) error {
    coeffs := r1cs.Coefficients
    constraints := r1cs.GetR1Cs()
//     fmt.Println("Number of constraints:", len(constraints))

    f, err := os.Create(filePath)
    if err != nil {
        return err
    }
    defer f.Close()

    if err := binary.Write(f, binary.LittleEndian, uint32(len(coeffs))); err != nil {
        return err
    }
    for _, c := range coeffs {
        b := c.Bytes()
        padded := make([]byte, 32)
        copy(padded[32-len(b):], b[:])
        if _, err := f.Write(padded); err != nil {
            return err
        }
    }

    if err := binary.Write(f, binary.LittleEndian, uint32(len(constraints))); err != nil {
        return err
    }
    for _, c := range constraints {
        nL := uint32(len(c.L))
        nR := uint32(len(c.R))
        nO := uint32(len(c.O))
        if err := binary.Write(f, binary.LittleEndian, nL); err != nil {
            return err
        }
        if err := binary.Write(f, binary.LittleEndian, nR); err != nil {
            return err
        }
        if err := binary.Write(f, binary.LittleEndian, nO); err != nil {
            return err
        }

        writeTerm := func(term constraint.Term) error {
            if err := binary.Write(f, binary.LittleEndian, uint32(term.WireID())); err != nil {
                return err
            }
            return binary.Write(f, binary.LittleEndian, uint32(term.CID))
        }
        for _, t := range c.L {
            if err := writeTerm(t); err != nil {
                return err
            }
        }
        for _, t := range c.R {
            if err := writeTerm(t); err != nil {
                return err
            }
        }
        for _, t := range c.O {
            if err := writeTerm(t); err != nil {
                return err
            }
        }
    }
    return nil
}


