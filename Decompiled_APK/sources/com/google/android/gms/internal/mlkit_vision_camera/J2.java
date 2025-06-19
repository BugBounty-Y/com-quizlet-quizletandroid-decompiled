package com.google.android.gms.internal.mlkit_vision_camera;

import android.text.SpannableStringBuilder;
import android.text.TextUtils;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.quizlet.features.notes.detail.composables.magicnotesdetail.C4389h;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import kotlin.collections.C4930v;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Regex;
import kotlin.text.StringsKt;
import org.wordpress.aztec.spans.C5168p;
import org.wordpress.aztec.spans.C5170s;
import org.wordpress.aztec.spans.C5172u;

/* loaded from: classes2.dex */
public abstract class J2 {
    public static final void a(Function0 onStart, Function0 onStop, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Intrinsics.checkNotNullParameter(onStart, "onStart");
        Intrinsics.checkNotNullParameter(onStop, "onStop");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1947834473);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(onStart) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(onStop) ? 32 : 16;
        }
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.lifecycle.J j = (androidx.lifecycle.J) c0814p.j(androidx.lifecycle.compose.g.a);
            c0814p.X(2006822900);
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (objI == v) {
                c0814p.i0(onStart);
                objI = onStart;
            }
            Function0 function0 = (Function0) objI;
            Object objG = com.google.android.gms.measurement.internal.Z.g(2006824307, c0814p, false);
            if (objG == v) {
                c0814p.i0(onStop);
                objG = onStop;
            }
            Function0 function02 = (Function0) objG;
            c0814p.p(false);
            c0814p.X(2006826537);
            boolean zH = c0814p.h(j);
            Object objI2 = c0814p.I();
            if (zH || objI2 == v) {
                objI2 = new androidx.lifecycle.compose.d(j, function0, function02, 17);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            C0776c.d(j, (Function1) objI2, c0814p);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4389h(onStart, onStop, i, 1);
        }
    }

    public static final String b(String content, boolean z) {
        boolean z2;
        Intrinsics.checkNotNullParameter(content, "content");
        String strE = "";
        org.jsoup.nodes.g gVarC = AbstractC3383q2.c(kotlin.text.D.o(e(content, "iframe", "iframe-replacement-0x0"), "<aztec_cursor>", "", false));
        org.jsoup.nodes.f fVar = new org.jsoup.nodes.f();
        fVar.e = !z;
        gVarC.j = fVar;
        org.wordpress.aztec.util.b.b(gVarC);
        if (z) {
            org.jsoup.parser.C cS = gVarC.S("*");
            Intrinsics.checkNotNullExpressionValue(cS, "select(...)");
            ArrayList arrayList = new ArrayList();
            Iterator it2 = cS.iterator();
            while (it2.hasNext()) {
                Object next = it2.next();
                org.jsoup.nodes.i iVar = (org.jsoup.nodes.i) next;
                if (!iVar.L() && Intrinsics.b(iVar.d.a, "span") && iVar.h().size() == 0) {
                    arrayList.add(next);
                }
            }
            Iterator it3 = arrayList.iterator();
            while (it3.hasNext()) {
                ((org.jsoup.nodes.i) it3.next()).y();
            }
            String strM = gVarC.V().M();
            Intrinsics.checkNotNullExpressionValue(strM, "html(...)");
            String htmlContent = e(e(strM, "iframe-replacement-0x0", "iframe"), "<p>(?:<br ?/?>| |\ufeff| )*</p>", "<p>&nbsp;</p>");
            Intrinsics.checkNotNullParameter(htmlContent, "htmlContent");
            boolean z3 = true;
            int length = htmlContent.length() - 1;
            int i = 0;
            boolean z4 = false;
            while (i <= length) {
                boolean z5 = Intrinsics.g(htmlContent.charAt(!z4 ? i : length), 32) <= 0;
                if (z4) {
                    if (!z5) {
                        break;
                    }
                    length--;
                } else if (z5) {
                    i++;
                } else {
                    z4 = true;
                }
            }
            if (!TextUtils.isEmpty(htmlContent.subSequence(i, length + 1).toString())) {
                if (StringsKt.G(htmlContent, "<pre", false) || StringsKt.G(htmlContent, "<script", false)) {
                    htmlContent = new Regex("<(pre|script)[^>]*>[\\s\\S]+?</\\1>").f(htmlContent, org.wordpress.aztec.source.a.c);
                    z2 = true;
                } else {
                    z2 = false;
                }
                if (StringsKt.G(htmlContent, "[caption", false)) {
                    Pattern patternCompile = Pattern.compile("\\[caption[\\s\\S]+?\\[/caption]");
                    Intrinsics.checkNotNullExpressionValue(patternCompile, "compile(...)");
                    Matcher matcher = patternCompile.matcher(htmlContent);
                    Intrinsics.checkNotNullExpressionValue(matcher, "matcher(...)");
                    StringBuffer stringBuffer = new StringBuffer();
                    if (matcher.find()) {
                        String strSubstring = htmlContent.substring(matcher.start(), matcher.end());
                        Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
                        String strReplaceFirst = Pattern.compile("[\\r\\n\\t]+").matcher(e(strSubstring, "<br([^>]*)>", "<wp-temp-br$1>")).replaceFirst("");
                        Intrinsics.checkNotNullExpressionValue(strReplaceFirst, "replaceFirst(...)");
                        matcher.appendReplacement(stringBuffer, Matcher.quoteReplacement(strReplaceFirst));
                    }
                    matcher.appendTail(stringBuffer);
                    htmlContent = stringBuffer.toString();
                    Intrinsics.checkNotNullExpressionValue(htmlContent, "toString(...)");
                } else {
                    z3 = false;
                }
                if (StringsKt.G(htmlContent, "<hr", false)) {
                    htmlContent = e(htmlContent, "<hr ?/?>", "<hr>");
                }
                String strE2 = e(e(e(e(e(e(e(e(e(e(e(e(e(e(htmlContent, "\\s*</(blockquote|ul|ol|li|table|thead|tbody|tfoot|tr|th|td|h[1-6]|fieldset|div|p)>\\s*", "</$1>\n"), "\\s*<((?:blockquote|ul|ol|li|table|thead|tbody|tfoot|tr|th|td|h[1-6]|fieldset|div|p)(?: [^>]*)?)>", "\n<$1>"), "\\s*<(!--.*?--|hr)>\\s*", "\n\n<$1>\n\n"), "(<p [^>]+>.*?)</p>", "$1</p#>"), "(?i)<div( [^>]*)?>\\s*<p>", "<div$1>\n\n"), "(?i)\\s*<p>", ""), "(?i)\\s*</p>\\s*", "\n\n"), "\\n[\\s\\u00a0]+\\n", "\n\n"), "(?i)\\s*<br ?/?>\\s*", "\n"), "\n\n<div", "\n<div"), "</div>\n\n", "</div>\n"), "(?i)\\s*\\[caption([^\\[]+)\\[/caption\\]\\s*", "\n\n[caption$1[/caption]\n\n"), "caption\\]\\n\\n+\\[caption", "caption]\n\n[caption"), "<li([^>]*)>", "\t<li$1>");
                if (StringsKt.G(strE2, "<option", false)) {
                    strE2 = e(e(strE2, "\\s*<option", "\n<option"), "\\s*</select>", "\n</select>");
                }
                if (StringsKt.G(strE2, "<object", false)) {
                    Pattern patternCompile2 = Pattern.compile("<object[\\s\\S]+?</object>");
                    Intrinsics.checkNotNullExpressionValue(patternCompile2, "compile(...)");
                    Matcher matcher2 = patternCompile2.matcher(strE2);
                    Intrinsics.checkNotNullExpressionValue(matcher2, "matcher(...)");
                    StringBuffer stringBuffer2 = new StringBuffer();
                    if (matcher2.find()) {
                        String strSubstring2 = strE2.substring(matcher2.start(), matcher2.end());
                        Intrinsics.checkNotNullExpressionValue(strSubstring2, "substring(...)");
                        String strReplaceFirst2 = Pattern.compile("[\\r\\n]+").matcher(strSubstring2).replaceFirst("");
                        Intrinsics.checkNotNullExpressionValue(strReplaceFirst2, "replaceFirst(...)");
                        matcher2.appendReplacement(stringBuffer2, Matcher.quoteReplacement(strReplaceFirst2));
                    }
                    matcher2.appendTail(stringBuffer2);
                    strE2 = stringBuffer2.toString();
                    Intrinsics.checkNotNullExpressionValue(strE2, "toString(...)");
                }
                String strE3 = e(e(e(e(e(strE2, "</p#>", "</p>"), "\\s*(<p [^>]+>[\\s\\S]*?</p>)", "\n$1"), "^\\s+", ""), "[\\s\\u00a0]+$", ""), "&nbsp;", " ");
                if (z2) {
                    strE3 = e(strE3, "<wp-line-break>", "\n");
                }
                strE = strE3;
                if (z3) {
                    strE = e(strE, "<wp-temp-br([^>]*)>", "<br$1>");
                }
            }
        } else {
            String strM2 = gVarC.V().M();
            Intrinsics.checkNotNullExpressionValue(strM2, "html(...)");
            strE = e(e(e(e(e(strM2, "iframe-replacement-0x0", "iframe"), "(?<!</?(div|br|blockquote|ul|ol|li|p|pre|h1|h2|h3|h4|h5|h6|iframe|hr)>)\n<((?!/?(div|br|blockquote|ul|ol|li|p|pre|h1|h2|h3|h4|h5|h6|iframe|hr)).*?)>", "<$2>"), "<(/?(?!div|br|blockquote|ul|ol|li|p|pre|h1|h2|h3|h4|h5|h6|iframe|hr).)>\n(?!</?(div|br|blockquote|ul|ol|li|p|pre|h1|h2|h3|h4|h5|h6|iframe|hr)>)", "<$1>"), "([\t ]*)(<br>)(?!\n)", "$1$2\n$1"), ">([\t ]*)(<br>)", ">\n$1$2");
        }
        return StringsKt.g0(strE).toString();
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static final void c(SpannableStringBuilder text, boolean z) {
        boolean z2;
        Intrinsics.checkNotNullParameter(text, "text");
        if (z) {
            Object[] objArr = (C5172u[]) text.getSpans(0, text.length(), C5172u.class);
            Intrinsics.d(objArr);
            boolean z3 = true;
            if (objArr.length > 1) {
                C4930v.t(objArr, new androidx.camera.core.streamsharing.a(text, 9));
            }
            int length = objArr.length;
            int i = 0;
            while (i < length) {
                Object obj = objArr[i];
                int spanStart = text.getSpanStart(obj);
                int spanEnd = text.getSpanEnd(obj);
                if (text.charAt(spanStart) == '\n') {
                    Object[] spans = text.getSpans(spanEnd, spanEnd + 1, org.wordpress.aztec.spans.L.class);
                    Intrinsics.checkNotNullExpressionValue(spans, "getSpans(...)");
                    ArrayList arrayList = new ArrayList();
                    int length2 = spans.length;
                    int i2 = 0;
                    while (i2 < length2) {
                        Object obj2 = spans[i2];
                        Object obj3 = (org.wordpress.aztec.spans.L) obj2;
                        boolean z4 = z3;
                        if ((!(obj3 instanceof org.wordpress.aztec.spans.T) || ((org.wordpress.aztec.spans.T) obj3).b.getLength() != 0) && text.getSpanStart(obj3) == spanEnd) {
                            arrayList.add(obj2);
                        }
                        i2++;
                        z3 = z4;
                    }
                    z2 = z3;
                    if (arrayList.isEmpty()) {
                        text.insert(spanEnd, "\n");
                    }
                } else {
                    z2 = z3;
                }
                Object[] spans2 = text.getSpans(spanStart, spanEnd, C5168p.class);
                Intrinsics.checkNotNullExpressionValue(spans2, "getSpans(...)");
                ArrayList arrayList2 = new ArrayList();
                for (Object obj4 : spans2) {
                    if (text.getSpanEnd((C5168p) obj4) == spanEnd) {
                        arrayList2.add(obj4);
                    }
                }
                if (arrayList2.isEmpty()) {
                    Object[] spans3 = text.getSpans(spanStart, spanEnd, org.wordpress.aztec.spans.T.class);
                    Intrinsics.checkNotNullExpressionValue(spans3, "getSpans(...)");
                    ArrayList arrayList3 = new ArrayList();
                    for (Object obj5 : spans3) {
                        if (((org.wordpress.aztec.spans.T) obj5).b.getLength() != 0) {
                            arrayList3.add(obj5);
                        }
                    }
                    if (arrayList3.isEmpty()) {
                        Object[] spans4 = text.getSpans(spanStart, spanEnd, C5170s.class);
                        Intrinsics.checkNotNullExpressionValue(spans4, "getSpans(...)");
                        for (Object obj6 : spans4) {
                            text.removeSpan((C5170s) obj6);
                        }
                    }
                }
                i++;
                z3 = z2;
            }
            boolean z5 = z3;
            Object[] spans5 = text.getSpans(0, text.length(), org.wordpress.aztec.spans.T.class);
            Intrinsics.checkNotNullExpressionValue(spans5, "getSpans(...)");
            for (Object obj7 : spans5) {
                Object obj8 = (org.wordpress.aztec.spans.T) obj7;
                int spanStart2 = text.getSpanStart(obj8);
                int spanEnd2 = text.getSpanEnd(obj8);
                int iM = StringsKt.M(text, "\n\n", spanStart2, false, 4);
                if (iM != -1 && iM < spanEnd2) {
                    int i3 = iM + 1;
                    text.setSpan(obj8, spanStart2, i3, text.getSpanFlags(obj8));
                    text.setSpan(new C5170s(), i3, iM + 2, text.getSpanFlags(obj8));
                }
            }
            Object[] spans6 = text.getSpans(0, text.length(), org.wordpress.aztec.spans.T.class);
            Intrinsics.checkNotNullExpressionValue(spans6, "getSpans(...)");
            ArrayList arrayList4 = new ArrayList();
            for (Object obj9 : spans6) {
                org.wordpress.aztec.spans.T t = (org.wordpress.aztec.spans.T) obj9;
                boolean z6 = t.b.getLength() == 0 ? z5 : false;
                boolean z7 = (!(t instanceof org.wordpress.aztec.spans.B) || ((org.wordpress.aztec.spans.B) t).d() == null) ? false : z5;
                boolean z8 = text.getSpanStart(t) == text.getSpanEnd(t) + (-1) ? z5 : false;
                if ((z6 && !z7) || z8) {
                    arrayList4.add(obj9);
                }
            }
            Iterator it2 = arrayList4.iterator();
            while (it2.hasNext()) {
                text.removeSpan((org.wordpress.aztec.spans.T) it2.next());
            }
        }
    }

    public static final String d(String formattedHtml, boolean z, boolean z2) {
        boolean z3;
        String string;
        Intrinsics.checkNotNullParameter(formattedHtml, "html");
        if (!z) {
            return z2 ? formattedHtml : e(formattedHtml, "\\s*<(/?(div|br|blockquote|ul|ol|li|p|pre|h1|h2|h3|h4|h5|h6|iframe|hr)(.*?))>\\s*", "<$1>");
        }
        Intrinsics.checkNotNullParameter(formattedHtml, "formattedHtml");
        String strO = kotlin.text.D.o(formattedHtml, "<aztec_cursor></aztec_cursor>", "", false);
        boolean z4 = true;
        int length = strO.length() - 1;
        int i = 0;
        boolean z5 = false;
        while (i <= length) {
            boolean z6 = Intrinsics.g(strO.charAt(!z5 ? i : length), 32) <= 0;
            if (z5) {
                if (!z6) {
                    break;
                }
                length--;
            } else if (z6) {
                i++;
            } else {
                z5 = true;
            }
        }
        if (TextUtils.isEmpty(strO.subSequence(i, length + 1).toString())) {
            string = "";
        } else {
            if (StringsKt.G(strO, "<object", false)) {
                Pattern patternCompile = Pattern.compile("<object[\\s\\S]+?</object>");
                Intrinsics.checkNotNullExpressionValue(patternCompile, "compile(...)");
                Matcher matcher = patternCompile.matcher(strO);
                Intrinsics.checkNotNullExpressionValue(matcher, "matcher(...)");
                StringBuffer stringBuffer = new StringBuffer();
                while (matcher.find()) {
                    String strSubstring = strO.substring(matcher.start(), matcher.end());
                    Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
                    matcher.appendReplacement(stringBuffer, Matcher.quoteReplacement(e(strSubstring, "[\\r\\n]+", "")));
                }
                matcher.appendTail(stringBuffer);
                strO = stringBuffer.toString();
                Intrinsics.checkNotNullExpressionValue(strO, "toString(...)");
            }
            Pattern patternCompile2 = Pattern.compile("<[^<>]+>");
            Intrinsics.checkNotNullExpressionValue(patternCompile2, "compile(...)");
            Matcher matcher2 = patternCompile2.matcher(strO);
            Intrinsics.checkNotNullExpressionValue(matcher2, "matcher(...)");
            StringBuffer stringBuffer2 = new StringBuffer();
            while (matcher2.find()) {
                String strSubstring2 = strO.substring(matcher2.start(), matcher2.end());
                Intrinsics.checkNotNullExpressionValue(strSubstring2, "substring(...)");
                matcher2.appendReplacement(stringBuffer2, Matcher.quoteReplacement(e(strSubstring2, "[\\r\\n]+", "")));
            }
            matcher2.appendTail(stringBuffer2);
            String string2 = stringBuffer2.toString();
            Intrinsics.checkNotNullExpressionValue(string2, "toString(...)");
            if (StringsKt.G(string2, "<pre", false) || StringsKt.G(string2, "<script", false)) {
                string2 = new Regex("<(pre|script)[^>]*>[\\s\\S]+?</\\1>").f(string2, org.wordpress.aztec.source.a.b);
                z3 = true;
            } else {
                z3 = false;
            }
            if (StringsKt.G(string2, "[caption' )", false)) {
                Pattern patternCompile3 = Pattern.compile("\\[caption[\\s\\S]+?\\[/caption]");
                Intrinsics.checkNotNullExpressionValue(patternCompile3, "compile(...)");
                Matcher matcher3 = patternCompile3.matcher(string2);
                Intrinsics.checkNotNullExpressionValue(matcher3, "matcher(...)");
                StringBuffer stringBuffer3 = new StringBuffer();
                while (matcher3.find()) {
                    String strSubstring3 = string2.substring(matcher3.start(), matcher3.end());
                    Intrinsics.checkNotNullExpressionValue(strSubstring3, "substring(...)");
                    matcher3.appendReplacement(stringBuffer3, Matcher.quoteReplacement(e(strSubstring3, "<br([^>]*)>", "<wp-temp-br$1>")));
                    Pattern patternCompile4 = Pattern.compile("<[a-zA-Z0-9]+( [^<>]+)?>");
                    String strSubstring4 = string2.substring(matcher3.start(), matcher3.end());
                    Intrinsics.checkNotNullExpressionValue(strSubstring4, "substring(...)");
                    Matcher matcher4 = patternCompile4.matcher(strSubstring4);
                    StringBuffer stringBuffer4 = new StringBuffer();
                    while (matcher4.find()) {
                        String strSubstring5 = strSubstring4.substring(matcher4.start(), matcher4.end());
                        Intrinsics.checkNotNullExpressionValue(strSubstring5, "substring(...)");
                        String strReplaceFirst = Pattern.compile("[\\r\\n\\t]+").matcher(strSubstring5).replaceFirst(" ");
                        Intrinsics.checkNotNullExpressionValue(strReplaceFirst, "replaceFirst(...)");
                        matcher4.appendReplacement(stringBuffer4, Matcher.quoteReplacement(strReplaceFirst));
                    }
                    matcher4.appendTail(stringBuffer4);
                    matcher3.appendReplacement(stringBuffer3, Matcher.quoteReplacement(stringBuffer4.toString()));
                    String strSubstring6 = string2.substring(matcher3.start(), matcher3.end());
                    Intrinsics.checkNotNullExpressionValue(strSubstring6, "substring(...)");
                    matcher3.appendReplacement(stringBuffer3, Matcher.quoteReplacement(e(strSubstring6, "\\s*\\n\\s*", "<wp-temp-br />")));
                }
                matcher3.appendTail(stringBuffer3);
                string2 = stringBuffer3.toString();
                Intrinsics.checkNotNullExpressionValue(string2, "toString(...)");
            } else {
                z4 = false;
            }
            String strE = e(e(e(e(e(e(e(e(e(e(e(e(e(e(e(e(e(e(e(e(e(e(e(string2, "(?i)<br ?/?>\\s*<br ?/?>", "\n\n"), "(?i)(<(?:table|thead|tfoot|caption|col|colgroup|tbody|tr|td|th|div|dl|dd|dt|ul|ol|li|pre|form|map|area|blockquote|address|math|style|p|h[1-6]|hr|fieldset|legend|section|article|aside|hgroup|header|footer|nav|figure|details|menu|summary)(?: [^>]*)?>)", "\n$1"), "(?i)(</(?:table|thead|tfoot|caption|col|colgroup|tbody|tr|td|th|div|dl|dd|dt|ul|ol|li|pre|form|map|area|blockquote|address|math|style|p|h[1-6]|hr|fieldset|legend|section|article|aside|hgroup|header|footer|nav|figure|details|menu|summary)>)", "$1\n\n"), "(?i)(<!--(.*?)-->)", "\n$1\n\n"), "(?i)<hr ?/?>", "<hr>\n\n"), "(?i)\\s*<option", "<option"), "(?i)</option>\\s*", "</option>"), "\\r\\n|\\r", "\n"), "\\n\\s*\\n+", "\n\n"), "([\\s\\S]+?)\\n\\n", "<p>$1</p>\n"), "(?i)<p>\\s*?</p>", ""), "(?i)<p>\\s*(</?(?:table|thead|tfoot|caption|col|colgroup|tbody|tr|td|th|div|dl|dd|dt|ul|ol|li|pre|form|map|area|blockquote|address|math|style|p|h[1-6]|hr|fieldset|legend|section|article|aside|hgroup|header|footer|nav|figure|details|menu|summary)(?: [^>]*)?>)\\s*</p>", "$1"), "(?i)<p>(<li.+?)</p>", "$1"), "(?i)<p>\\s*<blockquote([^>]*)>", "<blockquote$1><p>"), "(?i)</blockquote>\\s*</p>", "</p></blockquote>"), "(?i)<p>\\s*(</?(?:div)(?: [^>]*)?>)", "$1<p>"), "(?i)(</?(?:div)(?: [^>]*)?>)\\s*</p>", "</p>$1"), "(?i)<p>\\s*(</?(?:table|thead|tfoot|caption|col|colgroup|tbody|tr|td|th|div|dl|dd|dt|ul|ol|li|pre|form|map|area|blockquote|address|math|style|p|h[1-6]|hr|fieldset|legend|section|article|aside|hgroup|header|footer|nav|figure|details|menu|summary)(?: [^>]*)?>)", "$1"), "(?i)(</?(?:table|thead|tfoot|caption|col|colgroup|tbody|tr|td|th|div|dl|dd|dt|ul|ol|li|pre|form|map|area|blockquote|address|math|style|p|h[1-6]|hr|fieldset|legend|section|article|aside|hgroup|header|footer|nav|figure|details|menu|summary)(?: [^>]*)?>)\\s*</p>", "$1"), "(?i)\\s*\\n", "<br>\n"), "(?i)(</?(?:table|thead|tfoot|caption|col|colgroup|tbody|tr|td|th|div|dl|dd|dt|ul|ol|li|pre|form|map|area|blockquote|address|math|style|p|h[1-6]|hr|fieldset|legend|section|article|aside|hgroup|header|footer|nav|figure|details|menu|summary)[^>]*>)\\s*<br ?/?>", "$1"), "(?i)<br ?/?>(\\s*</?(?:p|li|div|dl|dd|dt|th|pre|td|ul|ol)>)", "$1"), "(?i)(?:<p>|<br ?/?>)*\\s*\\[caption([^\\[]+)\\[/caption\\]\\s*(?:</p>|<br ?/?>)*", "[caption$1[/caption]");
            if (z3) {
                strE = e(strE, "<wp-line-break>", "<br>");
            }
            if (z4) {
                strE = e(strE, "<wp-temp-br([^>]*)>", "<br$1>");
            }
            string = StringsKt.g0(kotlin.text.D.o(strE, "\n", "", false)).toString();
        }
        org.jsoup.nodes.g gVarC = AbstractC3383q2.c(kotlin.text.D.o(string, "\n", "", false));
        org.jsoup.nodes.f fVar = new org.jsoup.nodes.f();
        fVar.e = false;
        gVarC.j = fVar;
        String strM = gVarC.V().M();
        Intrinsics.checkNotNullExpressionValue(strM, "html(...)");
        return strM;
    }

    public static String e(String str, String str2, String str3) {
        String strReplaceAll = Pattern.compile(str2).matcher(str).replaceAll(str3);
        Intrinsics.checkNotNullExpressionValue(strReplaceAll, "replaceAll(...)");
        return strReplaceAll;
    }
}
