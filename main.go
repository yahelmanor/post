package main

import (
	"crypto"
	"encoding/csv"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/yahelmanor/post/post-lib"
	"google.golang.org/protobuf/proto"

	_ "golang.org/x/crypto/sha3"
)

func main() {
	kFlag := flag.Int("k", 0, "k is the hardness parmeter")
	gFlag := flag.Bool("g", false, "apply genration mode")
	vFlag := flag.Bool("v", false, "apply verifection mode")

	flag.Parse()

	//that is the case when both g and v or nither.
	if *vFlag == *gFlag {
		if *vFlag {
			fmt.Println("only one of -g and -v shoul be applied")
		} else {
			fmt.Println("one of -g and -v shoul be applied")
		}
		flag.PrintDefaults()
		return
	}
	//no input file
	if flag.NArg() <= 0 {
		fmt.Println("no file was entered")
		flag.PrintDefaults()
		return
	}
	//if we are in genration mode, we must have k bigger then zero
	if *gFlag && *kFlag <= 0 {
		fmt.Println("in genration mode, k must be bigger then zero")
		flag.PrintDefaults()
		return
	}
	if *gFlag {
		ps := post.NewHashPost(crypto.SHA3_512)
		for _, fileName := range flag.Args() {
			f, err := os.Open(fileName)
			if err != nil {
				fmt.Fprintf(os.Stderr, "\033[31merror\033[0m while opening file %s : %v", fileName, err)
				continue
			}
			inp, _ := io.ReadAll(f)
			prf := ps.Gen(*kFlag, inp)
			fmt.Printf("%s,%x\n", hex.EncodeToString(inp), prf)
		}
	}
	if *vFlag {
		ps := post.NewHashPost(crypto.SHA3_512)
		for _, fileName := range flag.Args() {
			f, err := os.Open(fileName)
			if err != nil {
				fmt.Printf("\033[31merror\033[0m while opening file %s : %v\n", fileName, err)
				continue
			}
			csvR := csv.NewReader(f)
			ret, err := csvR.ReadAll()
			if err != nil {
				fmt.Printf("\033[31merror\033[0m while reading %s: %v", fileName, err)
			}
			for i := range ret {
				if len(ret[i]) < 2 {
					continue
				}
				inp, err1 := hex.DecodeString(ret[i][0])
				prf, err2 := hex.DecodeString(ret[i][1])
				if err1 != nil || err2 != nil {
					fmt.Printf("%s(%d): \033[31mfailed\033[0m, %v and %v\n", fileName, i, err1, err2)
				}
				if ok, err := ps.Ver(inp, prf); !ok {
					fmt.Printf("%s(%d): \033[31mfailed\033[0m, %v\n", fileName, i, err)
				} else {
					prof := post.Proof{}
					proto.Unmarshal(prf, &prof)
					fmt.Printf("%s(%d): \033[32mpassed\033[0m k = %d\n", fileName, i, prof.GetK())
				}
			}
		}
	}
}
