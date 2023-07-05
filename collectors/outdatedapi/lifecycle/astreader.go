package lifecycle

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
)

const (
	deprecatedTag  = "+k8s:prerelease-lifecycle-gen:deprecated="
	removedTag     = "+k8s:prerelease-lifecycle-gen:removed="
	replacementTag = "+k8s:prerelease-lifecycle-gen:replacement="
)

// AstReader read k8s source file and parse it
type AstReader struct {
}

// NewAstReader instantiate new AST reader
func NewAstReader() AstReader {
	return AstReader{}
}

// AstData store k8s source ast data
type AstData struct {
	group        string
	recv         string
	methodName   string
	returnParams []string
}

type AstObjComments struct {
	Kind       string
	Deprecated string
	Removed    string
	Replaced   string
}

// AnalyzeComments scan k8s types source file parse it generation comments and return Kind , deprecate,removed and replacements versions
func (ar AstReader) AnalyzeComments(data string) ([]AstObjComments, error) {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, "src.go", data, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	cmap := ast.NewCommentMap(fset, node, node.Comments)
	filtersCommantMap := make(map[ast.Node][]*ast.CommentGroup)
	for key, cm := range cmap {
		for _, com := range cm[0].List {
			if strings.Contains(com.Text, "+k8s:prerelease-lifecycle-gen:deprecated") {
				filtersCommantMap[key] = cm
			}
		}
	}
	astComments := make([]AstObjComments, 0)
	for key, vals := range filtersCommantMap {
		a, ok := key.(*ast.GenDecl)
		aComment := AstObjComments{}
		if ok {
			b, ok := a.Specs[0].(*ast.TypeSpec)
			if ok {
				aComment.Kind = b.Name.Name
				for _, val := range vals {
					for _, vl := range val.List {
						if strings.Contains(vl.Text, deprecatedTag) {
							tagValue, err := getTagValue(vl.Text, deprecatedTag)
							if err != nil {
								continue
							}
							aComment.Deprecated = tagValue
							continue
						}
						if strings.Contains(vl.Text, removedTag) {
							tagValue, err := getTagValue(vl.Text, removedTag)
							if err != nil {
								continue
							}
							aComment.Removed = tagValue
							continue
						}
						if strings.Contains(vl.Text, replacementTag) {
							tagValue, err := getTagValue(vl.Text, replacementTag)
							if err != nil {
								continue
							}
							aComment.Replaced = strings.ReplaceAll(tagValue, ",", ".")
							continue
						}
					}
				}
			}
			if len(aComment.Removed) != 0 && len(aComment.Deprecated) != 0 {
				astComments = append(astComments, aComment)
			}
		}
	}
	return astComments, nil
}

func getTagValue(tagValue, tagKey string) (string, error) {
	vals := strings.Split(tagValue, tagKey)
	if len(vals) != 2 {
		return "", fmt.Errorf("failed to parse tag values %s", tagValue)
	}
	return vals[1], nil
}

// Analyze scan k8s source file and return it method and return types data
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
			if len(ad.returnParams) == 3 {
				ad.group = ad.returnParams[0]
			}
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
	//deprecated and removal
	for _, val := range x.Results {
		if k, ok := val.(*ast.BasicLit); ok {
			results = append(results, k.Value)
		} else { // replacement
			if k, ok := val.(*ast.CompositeLit); ok {
				for _, el := range k.Elts {
					a := el.(ast.Expr).(*ast.KeyValueExpr) // nolint:gosimple
					results = append(results, a.Value.(*ast.BasicLit).Value)
				}
			}
		}
	}
	return results
}
