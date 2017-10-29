\NeedsTeXFormat{LaTeX2e}
\ProvidesClass{confpaper}[2014/6/17 conference paper latex class]

%%% Opitons
\DeclareOption*{\PassOptionsToClass{\CurrentOption}{extarticle}}

%%% Process given options
\ProcessOptions\relax

%%%
%%%  Load base
%%%
\LoadClass[pdftex,letterpaper]{extarticle}

\RequirePackage{ifthen}

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%%
%%%  Custom variables to be set appropriately.
%%%
<<<<<<< HEAD
\newcommand{\AUTHORS}{Anne Edmundson, Nick Feamster, Jennifer}
\newcommand{\TITLE}{OCD: Oblivious Content Distribution}
\newcommand{\KEYWORDS}{Keywords}
\newcommand{\CONFERENCE}{Conference}
\newcommand{\PAGENUMBERS}{yes} % "yes" or "no"
\newcommand{\COMMENTS}{no}
\newcommand{\COLOR}{no}
=======
\newcommand{\AUTHORS}{Anonymous}
\newcommand{\TITLE}{The Impact of DNS on Tor's Anonymity}
\newcommand{\KEYWORDS}{Keywords}
\newcommand{\CONFERENCE}{Conference}
\newcommand{\PAGENUMBERS}{yes} % "yes" or "no"
\newcommand{\TABLECAPTIONS}{bottom} % "top" or "bottom". Silly IEEE formatting
\newcommand{\COLOR}{yes}
>>>>>>> 0113d4517af0dd808a91f4f1dba7f21f5472f044
\newcommand{\showComments}{yes}
\newcommand{\comment}[1]{}
\newcommand{\onlyAbstract}{no}

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%%
%%%  ACM Fonts.
%%%
\newfont{\secfnt}{ptmb8t at 12pt}
\newfont{\secit}{ptmbi8t at 12pt}     %13 Jan 00 gkmt
\newfont{\subsecfnt}{ptmri8t at 11pt}
\newfont{\subsecit}{ptmbi8t at 11pt}  % 
\newfont{\ttlfnt}{phvb8t at 18pt}
\newfont{\ttlit}{phvbo8t at 18pt}     % GM 2/4/2000
\newfont{\subttlfnt}{phvr8t at 14pt}
\newfont{\subttlit}{phvro8t at 14pt}  % GM 2/4/2000
\newfont{\subttlbf}{phvb8t at 14pt}   % 13 Jan 00 gkmt
\newfont{\aufnt}{phvr8t at 12pt}
\newfont{\auit}{phvro8t at 12pt}      % GM 2/4/2000
\newfont{\affaddr}{phvr8t at 10pt}
\newfont{\affaddrit}{phvro8t at 10pt} % GM 2/4/2000
\newfont{\eaddfnt}{phvr8t at 12pt}
\newfont{\ixpt}{ptmr8t at 9pt}
\newfont{\confname}{ptmri8t at 8pt}
\newfont{\crnotice}{ptmr8t at 8pt}
\newfont{\ninept}{ptmr8t at 9pt}

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%
%%% IEEE Formatting - Uncomment to get IEEE-Style Section headings
%%%

<<<<<<< HEAD
%
% \renewcommand{\thesection}{\Roman{section}} 
% \renewcommand{\thesubsection}{\thesection.\Alph{subsection}}
%
% \titleformat{\section}%                     % IEEE/ACM: caps + period
%   {\centering\sc}{\roman{section}.\quad}{0pt}{}
%
% \titleformat{\subsection}%                     % IEEE/ACM: caps + period
%   {\flushleft\it}{\Alph{subsection}.\quad}{0pt}{}
%
% \titleformat{\subsubsection}%                     % IEEE/ACM: caps + period
%   {\flushleft\it}{\Alph{subsection}.\arabic{subsubsection}.\quad}{0pt}{}


=======
\RequirePackage[compact]{titlesec}

\renewcommand{\baselinestretch}{0.95}

\usepackage[runin]{abstract}

\renewcommand{\abstractname}{~~~Abstract---\relax}
\renewcommand{\abstractnamefont}{\normalfont\footnotesize \fontshape{\itdefault}\fontseries{\bfdefault}\selectfont}
\renewcommand{\abstracttextfont}{\normalfont\footnotesize\bfseries}
\renewcommand{\absleftindent}{0pt}
\renewcommand{\absrightindent}{0pt}

\renewcommand{\thesection}{\Roman{section}} 
\renewcommand{\thesubsection}{\thesection.\Alph{subsection}}

\titleformat{\section}%                     % IEEE/ACM: caps + period
{\centering\sc}{\roman{section}.\quad}{0pt}{}

\titleformat{\subsection}%                     % IEEE/ACM: caps + period
{\flushleft\it}{\Alph{subsection}.\quad}{0pt}{}

\titleformat{\subsubsection}%                     % IEEE/ACM: caps + period
{\flushleft\it}{\Alph{subsection}.\arabic{subsubsection}.\quad}{0pt}{}


\newcommand{\tabcaptext}{}
\ifthenelse{\equal{\TABLECAPTIONS}{top}}{%
\newcommand{\topcap}[1]{\caption{#1}}
\newcommand{\bottomcap}[1]{}
}
{
\newcommand{\topcap}[1]{}
\newcommand{\bottomcap}[1]{\caption{#1}}
}
>>>>>>> 0113d4517af0dd808a91f4f1dba7f21f5472f044

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%%
%%%  Page Setup
%%%
\RequirePackage{balance}
\RequirePackage{tabulary}
\RequirePackage{url}
<<<<<<< HEAD
\RequirePackage{ifthen}
%\RequirePackage{dvips}



%%%%%%% Colors
\usepackage[dvips]{color}
\definecolor{red}{rgb}{0.5,0.0,0.0}
\definecolor{darkgreen}{rgb}{0,0.4,0}
\definecolor{navyblue}{rgb}{0,0,.5}
\definecolor{violet}{rgb}{0.4,0.0,0.4}
\definecolor{mymagenta}{cmyk}{0,0.6,0,0.4}
\definecolor{litegreen}{cmyk}{.25,0,0.75,0.1}
\definecolor{orange}{cmyk}{.25,0.4,0.4,0}
\definecolor{cyan}{cmyk}{0.7,0,0,0.2}
\definecolor{myred}{rgb}{0.7,0.0,0.0}
\definecolor{myblue}{rgb}{0.0,0.0,0.5}
\definecolor{mygreen}{rgb}{0.0,0.3,0.0}

\newcommand{\txr}[1]{\textcolor{myred}{#1}}
\newcommand{\txR}[1]{\textcolor{red}{#1}}
\newcommand{\txb}[1]{\textcolor{myblue}{#1}}
\newcommand{\txg}[1]{\textcolor{mygreen}{#1}}
\newcommand{\txm}[1]{\textcolor{magenta}{#1}}

\newcommand{\mat}[1]{\textcolor{mymagenta}{#1}}
\newcommand{\defn}[1]{\textcolor{myblue}{#1}}
\newcommand{\note}[1]{\textcolor{mygreen}{#1}}
\renewcommand{\emph}[1]{\textcolor{red}{\em\bf #1}}
\newcommand{\black}[1]{\textcolor{black}{#1}}
\newcommand{\bbox}[1]{\black{\mbox{#1}}}
=======
>>>>>>> 0113d4517af0dd808a91f4f1dba7f21f5472f044

\special{papersize=8.5in,11in}
\setlength{\pdfpagewidth}{8.5in}
\setlength{\pdfpageheight}{11in}

\ifthenelse{\equal{\PAGENUMBERS}{yes}}{%
\RequirePackage[nohead,
% SIGCOMM/ACM
<<<<<<< HEAD
    left=0.75in,right=0.75in,top=0.75in, bottom=1in,
    columnsep=0.33in
% USENIX
%    left=1.0in,right=1.0in,top=1.0in,
%    footskip=0.5in,bottom=1.0in,   % Room for page numbers
%    columnsep=0.33in
% IEEE
%            left=0.75in,right=0.75in,top=0.75in, bottom=1in,
%            columnsep=0.2in
=======
%    left=0.75in,right=0.75in,top=0.75in, bottom=1in,
%    columnsep=0.33in
% USENIX
%    left=1.0in,right=1.0in,top=1.0in,
%    footskip=0.5in,bottom=1.0in,   % Room for page numbers
%    columnsep=0.25in
% IEEE
            left=0.75in,right=0.75in,top=0.75in, bottom=1in,
            columnsep=0.2in
>>>>>>> 0113d4517af0dd808a91f4f1dba7f21f5472f044
% Custom
%    left=1.5in,right=1.5in,top=1.0in,
%    footskip=0.5in,bottom=1.0in,   % Room for page numbers
%    columnsep=0.25in
  ]{geometry}
}{%
<<<<<<< HEAD
\RequirePackage[noheadfoot,left=0.75in,right=0.75in,top=0.75in,
    footskip=0.5in,bottom=1in,
    columnsep=0.33in
=======
  \RequirePackage[noheadfoot,
  left=0.75in,right=0.75in,top=0.75in,bottom=1in,
  columnsep=0.15in
>>>>>>> 0113d4517af0dd808a91f4f1dba7f21f5472f044
  ]{geometry}
}

%%%
%%%  Renew "itemize" environment
%%%
\renewenvironment{itemize}
{\begin{list}{$\bullet$}{
    \setlength{\labelsep}{4pt}
    \setlength{\labelwidth}{3pt}
    \setlength{\rightmargin}{0pt}
    \setlength{\leftmargin}{0pt}
    \addtolength{\leftmargin}{\labelwidth}
    \addtolength{\leftmargin}{\labelsep}
}}{\end{list}}

%%%
%%%  Captions
%%%
%\RequirePackage[font=bf]{caption}
<<<<<<< HEAD
\RequirePackage[font=small,format=plain,labelfont=bf,textfont=it,aboveskip=3.5pt]{caption}
\RequirePackage{subcaption}
=======
\RequirePackage[font=footnotesize,format=plain,labelfont=bf,textfont=it]{caption}
%\RequirePackage{subcaption}
>>>>>>> 0113d4517af0dd808a91f4f1dba7f21f5472f044
%% Space between figure and caption (assuming caption
%% is below figure)
%\RequirePackage[font=bf,aboveskip=0pt]{caption} % SPACE
%% Space between caption and body text of document
<<<<<<< HEAD
\addtolength{\textfloatsep}{-7pt} % SPACE
=======
\addtolength{\textfloatsep}{-12pt} % SPACE
>>>>>>> 0113d4517af0dd808a91f4f1dba7f21f5472f044

%%%
%%%  Section headings
%%%
%\RequirePackage{titlesec}
%\titlespacing{\paragraph}{0pt}{*1}{*1} % SPACE
<<<<<<< HEAD
\RequirePackage[compact]{titlesec}  % SPACE
%\titleformat{\section}%  % IEEE/ACM: caps + period
% {\bf\large\uppercase}{\thesection.\quad}{0pt}{}
\titleformat{\section}{\bf\large}{\thesection}{8pt}{} % USENIX
=======
%\RequirePackage[compact]{titlesec}  % SPACE
%\titleformat{\section}%  % IEEE/ACM: caps + period
% {\bf\large\uppercase}{\thesection.\quad}{0pt}{}
%\titleformat{\section}{\bf\large}{\thesection}{8pt}{} % USENIX
>>>>>>> 0113d4517af0dd808a91f4f1dba7f21f5472f044


%%%
%%%  Lists
%%%
\RequirePackage{paralist}
\RequirePackage{enumitem}
\setlist{itemsep=0pt,parsep=0pt}  % more compact lists

<<<<<<< HEAD
\renewcommand{\paragraph}[1]{\vspace*{0.03in}\noindent{\bf #1}}
=======
\renewcommand{\paragraph}[1]{\vspace*{0.03in}\noindent{\bf #1.}}
>>>>>>> 0113d4517af0dd808a91f4f1dba7f21f5472f044

%%%
%%%  Custom Environments
%%%
\RequirePackage{pifont}
\newcommand{\cmark}{\ding{51}}%
\newcommand{\xmark}{\ding{55}}%

%%%
%%%  Header / Footer
%%%
\RequirePackage{fancyhdr}
\renewcommand{\headrulewidth}{0pt}

\ifthenelse{\equal{\PAGENUMBERS}{yes}}{%
<<<<<<< HEAD
  \pagestyle{plain}
=======

\fancypagestyle{version}{\fancyhf{}\renewcommand{\headrulewidth}{0pt}\fancyfoot[R]{{\small Date: March 11, 2016}}}

\pagestyle{plain}
\renewcommand{\headrulewidth}{0pt}

>>>>>>> 0113d4517af0dd808a91f4f1dba7f21f5472f044
}{%
  \pagestyle{empty}
}

%%%
%%%  Bibliography
%%%
<<<<<<< HEAD
%\RequirePackage[numbers]{natbib}
=======
>>>>>>> 0113d4517af0dd808a91f4f1dba7f21f5472f044
\RequirePackage{cite}

%%%
%%%  Footnotes / Endnotes
%%%
\interfootnotelinepenalty=10000  % Split footnotes are annoying

%% If you want endnodes, uncomment:
%\RequirePackage{endnotes}
%\RequirePackage{drafthead}
%\let\footnote=\endnote

%%%
%%%  Tables
%%%
\RequirePackage{booktabs}
\RequirePackage{color}
\RequirePackage{colortbl}
\RequirePackage{float}  % Must appear before hyperref to
                        % avoid weird PDF compile issues

%%%
%%%  Fonts
%%%
<<<<<<< HEAD
\RequirePackage[tt=false, type1=true]{libertine}
\RequirePackage[varqu]{zi4}
%\RequirePackage[libertine]{newtxmath}
\RequirePackage[T1]{fontenc}

\RequirePackage{mathptmx} % Times/Times-like math symbols
\RequirePackage{courier}
=======
\RequirePackage{mathptmx} % Times/Times-like math symbols
\RequirePackage{courier}
\RequirePackage[scaled=0.92]{helvet}
>>>>>>> 0113d4517af0dd808a91f4f1dba7f21f5472f044

%%%
%%%  PDF setup
%%%
\RequirePackage[breaklinks=true,filecolor=black,citecolor=blue,urlcolor=black,linkcolor=blue,colorlinks,pdfpagelabels,pdfpagelayout=SinglePage]{hyperref}


<<<<<<< HEAD
% ,pagebackref option stuff
=======
>>>>>>> 0113d4517af0dd808a91f4f1dba7f21f5472f044
% \renewcommand*{\backref}[1]{}
% \renewcommand*{\backrefalt}[4]{
%   \ifcase #1 %
%     (Not cited.) %
%   \or
%     {\small (Cited on page~#2.)}%
%   \else
%     {\small (Cited on pages~#2.)}%
%   \fi
% }
% \renewcommand*{\backrefsep}{, }
% \renewcommand*{\backreftwosep}{ and~}
% \renewcommand*{\backreflastsep}{ and~}

\hypersetup{%
pdfauthor = {\AUTHORS},
pdfsubject = {\CONFERENCE},
pdfkeywords = {\KEYWORDS},
bookmarksopen = {true}
}

%%
%%  Figure placeholder macros
%%
<<<<<<< HEAD
%\definecolor{placeholderbg}{rgb}{0.85,0.85,0.85}
%\newcommand{\placeholder}[1]{%
%\fcolorbox{black}{placeholderbg}{\parbox[top][1.5in][c]{0.95\columnwidth}{#1}}}
=======
\definecolor{placeholderbg}{rgb}{0.85,0.85,0.85}
\newcommand{\placeholder}[1]{%
\fcolorbox{black}{placeholderbg}{\parbox[top][1.5in][c]{0.95\columnwidth}{#1}}}
>>>>>>> 0113d4517af0dd808a91f4f1dba7f21f5472f044

%%%
%%%  Misc
%%%
\RequirePackage[pdftex]{graphicx}
\RequirePackage{soul}
<<<<<<< HEAD
\RequirePackage{subcaption}
=======
>>>>>>> 0113d4517af0dd808a91f4f1dba7f21f5472f044
\RequirePackage{amsthm}
\RequirePackage{amssymb}
\RequirePackage{listings}
\RequirePackage{tikz}
\usetikzlibrary{arrows}
<<<<<<< HEAD
=======
%\RequirePackage{subcaption}
>>>>>>> 0113d4517af0dd808a91f4f1dba7f21f5472f044

%\setlength{\parindent}{0pt}
%\setlength{\parskip}{\baselineskip}

\clubpenalty=10000  % Don't allow orphans
\widowpenalty=10000 % Don't allow widows

%%%
%%%  To appear/appeared in text on title page
%%%
\RequirePackage[absolute]{textpos}
\newcommand{\ToAppear}{%
\begin{textblock*}{\textwidth}(0.95in,0.4in)
\begin{flushright}
    %\noindent{\fbox{\textsf{Under submission---please do not redistribute.}}}
    %  --OR--
    \noindent{\small To appear in \textit{Proceedings of the XYZ}\\
    \noindent{\small \textit{Conference (XYZ'08)}, City, State, Month 2008}}
    %  --OR--
    %\noindent{\small In \textit{Proceedings of the XYZ}\\
    %\noindent{\small \textit{Conference (XYZ'08)}, City, State, Month 2008}}
\end{flushright}
\end{textblock*}
}

%%%
%%%  Sample ACM Copyright Block
%%%
\floatstyle{plain}
\newfloat{acmcr}{b}{acmcr}
\newcommand{\AcmCopyright}{%
\begin{acmcr}
\parbox[b]{20pc}{%
\footnotesize
Permission to make digital or hard copies of all or part of this work
for personal or classroom use is granted without fee provided that
copies are not made or distributed for profit or commercial advantage
and that copies bear this notice and the full citation on the first
page.  To copy otherwise, to republish, to post on servers or to
redistribute to lists, requires prior specific permission and/or a fee.

{\em Conference}, Month Date--Date, Year, Location\\
Copyright 200X ACM X-XXXXX-XX-X/XX/XX ...\$5.00}
\end{acmcr}}

%%%
%%%  Comments
%%%
<<<<<<< HEAD
%\newcommand{\note}[2]{
%    \ifthenelse{\equal{\showComments}{yes}}{\textcolor{#1}{#2}}{}
%}
%
%\newcommand{\xxx}[1]{\note{red}{#1}}
%\newcommand{\todo}[1]{\note{red}{\bf #1}}
=======
\newcommand{\note}[2]{
    \ifthenelse{\equal{\showComments}{yes}}{\textcolor{#1}{#2}}{}
}

\newcommand{\xxx}[1]{\note{red}{#1}}
\newcommand{\todo}[1]{\note{red}{\bf #1}}
>>>>>>> 0113d4517af0dd808a91f4f1dba7f21f5472f044

%%%
%%%  Abbreviations
%%%
<<<<<<< HEAD
\newcommand{\ie}{{\em i.e.}}
\newcommand{\eg}{{\em e.g.}}
\newcommand{\ea}{{\em et al.}}
=======
\newcommand{\ie}{{\em i.e.\xspace}}
\newcommand{\eg}{{\em e.g.\xspace}}
\newcommand{\ea}{{\em et al.\xspace}}
\newcommand{\etc}{{\em etc.}\xspace}
>>>>>>> 0113d4517af0dd808a91f4f1dba7f21f5472f044
\newcommand{\fp}{\vspace*{0.05in}\noindent}
\newcommand{\name}{NAME\xspace}

%%%
%%%  Theorems
%%%
\newtheoremstyle{tighter}
    {3pt}        % Space above
    {3pt}        % Space below
    {\em}        % Body font
    {}           % Indentation
    {\bfseries}  % Head font
    {:}          % Head punctuation
    {.5em}       % Head space
    {}           % Custom head spec
\theoremstyle{tighter}
\newtheorem{lesson}{Lesson}
\newtheorem{constraint}{Constraint}
%\newcommand{\lesson}[1]{\vspace{1em}{\centering\fbox{\parbox{0.95\columnwidth}{\centering\bf Lesson: #1}}}\vspace{1em}}

% This needs to be the last thing before \begin{document}
\RequirePackage{microtype}  % SPACE

%%%
%%% Additional Packages
%%%

\usepackage{multirow}
\usepackage{xspace}

<<<<<<< HEAD
\newlength{\codewidth}
\setlength{\codewidth}{\textwidth}
\addtolength{\codewidth}{-0.5in}

=======
\endinput
>>>>>>> 0113d4517af0dd808a91f4f1dba7f21f5472f044
