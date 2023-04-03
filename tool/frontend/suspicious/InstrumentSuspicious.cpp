#include <iostream>
#include <sstream>
#include <string>
#include <unordered_set>
#include <unordered_map>
#include <fstream>
#include <vector>

#include "../AngelixCommon.h"
#include "../util.h"
#include "SMTLIB2.h"

std::vector<int> vulnerableLocation;



void parse_locations(const char** argv, int offset){
	int count = offset;
	
	for(int i=0; i<4; i++)
		vulnerableLocation.push_back(atoi(argv[count++]));
	
}

bool isSuspicious(int beginLine, int beginCol, int endLine, int endCol) {
 	return (vulnerableLocation[0]==beginLine && 
		vulnerableLocation[1]==beginCol && 
		vulnerableLocation[2]==endLine && 
		vulnerableLocation[3]==endCol);
  
}


class StatementHandler : public MatchFinder::MatchCallback {
public:
  StatementHandler(Rewriter &Rewrite) : Rewrite(Rewrite) {}

  virtual void run(const MatchFinder::MatchResult &Result) override{
    if (const Stmt *stmt = Result.Nodes.getNodeAs<clang::Stmt>("repairable")) {
      SourceManager &srcMgr = Rewrite.getSourceMgr();

      SourceRange expandedLoc = getExpandedLoc(stmt, srcMgr);

      unsigned beginLine = srcMgr.getExpansionLineNumber(expandedLoc.getBegin());
      unsigned beginColumn = srcMgr.getExpansionColumnNumber(expandedLoc.getBegin());
      unsigned endLine = srcMgr.getExpansionLineNumber(expandedLoc.getEnd());
      unsigned endColumn = srcMgr.getExpansionColumnNumber(expandedLoc.getEnd());

      if (! isSuspicious(beginLine, beginColumn, endLine, endColumn)) {
        return;
      }

      std::cout << beginLine << " " << beginColumn << " " << endLine << " " << endColumn << "\n"
                << toString(stmt) << "\n";

      std::string indent(beginColumn-1, ' ');

      std::ostringstream stringStream;
	  std::string condition = "condition"+std::to_string(beginLine)+std::to_string(beginColumn);
      stringStream << "volatile int " << condition << ";\n"
	  			   << "if ("
                   << condition
				   << ") "
                   << toString(stmt)
                   << ";\n"
                   << indent
                   << "else "
                   << "exit(1)";
      std::string replacement = stringStream.str();

      Rewrite.ReplaceText(expandedLoc, replacement);
    }
  }

private:
  Rewriter &Rewrite;

};


class MyASTConsumer : public ASTConsumer {
public:
	MyASTConsumer(Rewriter &R) : HandlerForStatements(R)	
	{							 		
		Finder.addMatcher(InterestingStatement, &HandlerForStatements);
	}

	void HandleTranslationUnit(ASTContext &Context) override {
		Finder.matchAST(Context);
	}

private:
	StatementHandler HandlerForStatements;

	MatchFinder Finder;
	
};


class InstrumentSuspiciousAction : public ASTFrontendAction {
public:
  InstrumentSuspiciousAction() {}

  void EndSourceFileAction() override {
    FileID ID = TheRewriter.getSourceMgr().getMainFileID();
    if (INPLACE_MODIFICATION) {
      //overwriteMainChangedFile(TheRewriter);
      TheRewriter.overwriteChangedFiles();
    } else {
      TheRewriter.getEditBuffer(ID).write(llvm::outs());
    }
  }

  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI, StringRef file) override {
    TheRewriter.setSourceMgr(CI.getSourceManager(), CI.getLangOpts());
    return std::make_unique<MyASTConsumer>(TheRewriter);
  }

private:
  Rewriter TheRewriter;
};


// Apply a custom category to all command-line options so that they are the only ones displayed.
static llvm::cl::OptionCategory MyToolCategory("angelix options");


int main(int argc, const char **argv) {
	// CommonOptionsParser constructor will parse arguments and create a
	// CompilationDatabase.  In case of error it will terminate the program.
	parse_locations(argv, 2);
	argc = 2;
	// clang 16
	auto ExpectedParser = CommonOptionsParser::create(argc, argv, MyToolCategory);

	CommonOptionsParser &OptionsParser = ExpectedParser.get();

	//clang 11
	//CommonOptionsParser OptionsParser(argc, argv, MyToolCategory);

	// We hand the CompilationDatabase we created and the sources to run over into the tool constructor.
	ClangTool Tool(OptionsParser.getCompilations(), OptionsParser.getSourcePathList());

	return Tool.run(newFrontendActionFactory<InstrumentSuspiciousAction>().get());
}
