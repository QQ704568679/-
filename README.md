s-cms code audit

[suggested description]

In the "index.php" file of the root directory of CMS again.In
the process of application testing, it is detected that the tested Web application does not have sensitive character filtering 
function, which leads to the generation of SQL injection. The location of the 
vulnerability is marked in the following figure: 138, 146, 155, 166, 176, 186, line code,
among which the S_id variable has serious problems.
>> 
------------------------------------------ 
>> 
[additional information]

s-cms Latest version PHP version v3.0 debug
There is a SQL injection vulnerability in the source code.
The cause of the loophole is:
This vulnerability can trigger the vulnerability by constructing malicious code and can get sensitive information.
Methods that cause defects:
The index. PHP source code in the root directory of the website is 138, 146, 155, 166, 176, 186, 
among which the S_id variable is problematic and has not been filtered, 
resulting in a SQL injection vulnerability.

The following is the location of the vulnerability trigger：

Existing problems：
[76 lines of code in the code to 82 lines of code.]
[84 lines of code in the code to 95 lines of code.]
[97 lines of code in the code to 107 lines of code.]

switch ($U_type) {
    case "index":
        $page_info = ReplaceLableFlag(ReplaceTag(CreateHTMLReplace(CreateIndex(ReplacePart(LoadTemplate($style, 1))))));
        break;

    case "contact":
        $page_info = ReplaceLableFlag(ReplaceTag(CreateHTMLReplace(CreateContact(ReplacePart(LoadTemplate($style, 1))))));
        break;

    case "guestbook":
        $page_info = ReplaceLableFlag(ReplaceTag(CreateHTMLReplace(CreateGuestbook(ReplacePart(LoadTemplate($style, 1))))));
        break;

    case "bbs":
        Header("location:bbs");
        break;

    case "member":
        Header("location:member");
        break;

    case "text":
        if (getrs("select * from SL_text where T_id=" . $S_id, "T_title") == "") {
            box("The introduction of menu orientation has been deleted. Please re edit" menu management "., "back", "error");
        } else {
            $page_info = ReplaceLableFlag(ReplaceTag(CreateHTMLReplace(CreateText(ReplacePart(LoadTemplate($style, $S_id)) , $S_id))));
        }
        break;

    case "form":
        if (getrs("select * from SL_form where F_id=" . $S_id, "F_title") == "") {
            box("The introduction of menu orientation has been deleted. Please re edit" menu management "., "back", "error");
        } else {
            $page_info = ReplaceLableFlag(ReplaceTag(CreateHTMLReplace(CreateForm(ReplacePart(LoadTemplate($style, $S_id)) , $S_id))));
        }
        break;

    case "news":
        if (is_numeric($S_id)) {
            if (getrs("select * from SL_nsort where S_id=" . $S_id, "S_title") == "" && $S_id <> 0) {
                box("The news classification of menu orientation has been deleted. Please re edit" menu management "., "back", "error");
            } else {
                $page_info = ReplaceLableFlag(ReplaceTag(CreateHTMLReplace(CreateNewsList(ReplacePart(LoadTemplate($style, $S_id)) , $S_id, $S_page))));
            }
        } else {
            $page_info = ReplaceLableFlag(ReplaceTag(CreateHTMLReplace(CreateNewsList(ReplacePart(LoadTemplate($style, $S_id)) , $S_id, $S_page))));
        }
        break;

    case "newsinfo":
        if (getrs("select * from SL_news where N_id=" . $S_id, "N_title") == "") {
            box("The news does not exist or has been deleted.", "back", "error");
        } else {
            $page_info = ReplaceLableFlag(ReplaceTag(CreateHTMLReplace(CreateNewsInfo(ReplacePart(LoadTemplate($style, $S_id)) , $S_id))));
        }
        break;

    case "product":
        if (is_numeric($S_id)) {
            if (getrs("select * from SL_psort where S_id=" . $S_id, "S_title") == "" && $S_id > 0) {
                box("Menu oriented product classification has been deleted. Please re edit" menu management "., "back", "error");
            } else {
                $page_info = ReplaceLableFlag(ReplaceTag(CreateHTMLReplace(CreateProductList(ReplacePart(LoadTemplate($style, $S_id)) , $S_id, $S_page))));
            }
        } else {
            $page_info = ReplaceLableFlag(ReplaceTag(CreateHTMLReplace(CreateProductList(ReplacePart(LoadTemplate($style, $S_id)) , $S_id, $S_page))));
        }
        break;

    case "productinfo":
        if (getrs("select * from SL_product where P_id=" . $S_id, "P_title") == "") {
            box("The product does not exist or has been deleted"., "back", "error");
        } else {
            $page_info = ReplaceLableFlag(ReplaceTag(CreateHTMLReplace(CreateProductInfo(ReplacePart(LoadTemplate($style, $S_id)) , $S_id))));
        }
        break;

    default:
        $page_info = ReplaceLableFlag(ReplaceTag(CreateHTMLReplace(CreateIndex(ReplacePart(LoadTemplate($style, 1))))));
}


if ($_SESSION["f"] == 1) {
    echo cnfont($page_info, "f");
} else {
    echo cnfont($page_info, "j");
}

?>





Qiming Star Information Technology Group Limited by Share Ltd







[vulnerability]

Attackers can cause sensitive database information leakage by constructing malicious code.

Version information：

s-cms Latest version PHP version v3.0

POC：

http://127.0.0.1/1/?type=productinfo&S_id=140

payload：

AND 3994=3994

[restoration recommendations]

Restoring source code to prevent loopholes from happening again

[vulnerability type]

SQL injection vulnerability

[Supplier Business]

s-cms

[affected product code base]

s-cms Latest version PHP version v3.0

[affected components]

Users and administrators divulge information

[other attack types]

SQL injection vulnerability

[attack medium]

AND 3994=3994
