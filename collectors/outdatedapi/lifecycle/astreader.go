package main

import (
	"go/ast"
	"go/parser"
	"go/token"
)

//AstReader read k8s source file and parse it
type AstReader struct {
}

//NewAstReader instantiate new AST reader
func NewAstReader() AstReader {
	return AstReader{}
}

//AstData store k8s source ast data
type AstData struct {
	recv         string
	methodName   string
	returnParams []string
}

//Analyze scan k8s source file and return it method and return types data
func (ar AstReader) Analyze(code string) ([]AstData, error) {
	astDataArr := make([]AstData, 0)
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, "src.go", code, 0)
	if err != nil {
		return nil, err
	}
	ad := AstData{}
	ast.Inspect(node, func(n ast.Node) bool {
		switch x := n.(type) {
		// Find Return Statements
		case *ast.ReturnStmt:
			ad.returnParams = ar.updateMethodReturnParams(x)
			ad, astDataArr = ar.updateAst(ad, astDataArr)
			return true
		// Find Functions
		case *ast.FuncDecl:
			ar.updateDeclMethod(x, &ad)
			ad, astDataArr = ar.updateAst(ad, astDataArr)
			return true
		}
		return true
	})
	return astDataArr, nil
}

func (ar AstReader) updateDeclMethod(x *ast.FuncDecl, ad *AstData) {
	for _, v := range x.Recv.List {
		switch xv := v.Type.(type) {
		case *ast.StarExpr:
			if si, ok := xv.X.(*ast.Ident); ok {
				ad.recv = si.Name
				ad.methodName = x.Name.Name
			}
		}
	}
}

func (ar AstReader) updateAst(ad AstData, astDataArr []AstData) (AstData, []AstData) {
	if len(ad.recv) > 0 && len(ad.returnParams) > 0 && len(ad.methodName) > 0 {
		astDataArr = append(astDataArr, ad)
		ad = AstData{}
	}
	return ad, astDataArr
}

func (ar AstReader) updateMethodReturnParams(x *ast.ReturnStmt) []string {
	results := make([]string, 0)
	for _, val := range x.Results {
		if k, ok := val.(*ast.BasicLit); ok {
			results = append(results, k.Value)
		} else {
			if k, ok := val.(*ast.CompositeLit); ok {
				for _, el := range k.Elts {
					a := el.(ast.Expr).(*ast.KeyValueExpr)
					results = append(results, a.Value.(*ast.BasicLit).Value)
				}
			}
		}
	}
	return results
}
