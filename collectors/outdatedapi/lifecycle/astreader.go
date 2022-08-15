package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
)

type AstReader struct {
}

func NewAstReader() AstReader {
	return AstReader{}
}

type AstData struct {
	filePackage  string
	recv         string
	methodName   string
	returnParams []string
}

func (ar AstReader) Analyze(code string) ([]AstData, error) {
	astDataArr := make([]AstData, 0)
	fset := token.NewFileSet() // positions are relative to fset
	node, err := parser.ParseFile(fset, "src.go", code, 0)
	if err != nil {
		return nil, err
	}
	ad := AstData{}
	var pkg string
	ast.Inspect(node, func(n ast.Node) bool {
		// Find Return Statements
		switch x := n.(type) {
		case *ast.File:
			pkg = x.Name.String()
		case *ast.ReturnStmt:
			results := make([]string, 0)
			fmt.Println("\n\t")
			for _, val := range x.Results {
				if k, ok := val.(*ast.BasicLit); ok {
					fmt.Println(k.Value)
					results = append(results, k.Value)
				} else {
					if k, ok := val.(*ast.CompositeLit); ok {
						for _, el := range k.Elts {
							a := el.(ast.Expr).(*ast.KeyValueExpr)
							fmt.Println(a.Value.(*ast.BasicLit).Value)
							results = append(results, a.Value.(*ast.BasicLit).Value)
						}
					}
				}
			}
			ad.returnParams = results
			if len(ad.recv) > 0 && len(ad.returnParams) > 0 && len(ad.methodName) > 0 && len(ad.filePackage) > 0 {
				astDataArr = append(astDataArr, ad)
				ad = AstData{}
			}
			return true
		// Find Functions
		case *ast.FuncDecl:
			for _, v := range x.Recv.List {
				switch xv := v.Type.(type) {
				case *ast.StarExpr:
					if si, ok := xv.X.(*ast.Ident); ok {
						ad.recv = si.Name
						ad.methodName = x.Name.Name
						ad.filePackage = pkg
					}
				}
				if len(ad.recv) > 0 && len(ad.returnParams) > 0 && len(ad.methodName) > 0 && len(ad.filePackage) > 0 {
					astDataArr = append(astDataArr, ad)
					ad = AstData{}
				}
			}
			return true
		}
		return true
	})
	return astDataArr, nil
}
