package org.wordpress.aztec;

import android.content.Context;
import android.text.SpannableStringBuilder;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_camera.D2;
import java.util.Iterator;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.spans.AztecRelativeSizeBigSpan;
import org.wordpress.aztec.spans.AztecRelativeSizeSmallSpan;
import org.wordpress.aztec.spans.AztecStyleBoldSpan;
import org.wordpress.aztec.spans.AztecStyleCiteSpan;
import org.wordpress.aztec.spans.AztecStyleEmphasisSpan;
import org.wordpress.aztec.spans.AztecStyleItalicSpan;
import org.wordpress.aztec.spans.AztecStyleStrongSpan;
import org.wordpress.aztec.spans.AztecSubscriptSpan;
import org.wordpress.aztec.spans.AztecSuperscriptSpan;
import org.wordpress.aztec.spans.AztecTypefaceMonospaceSpan;
import org.wordpress.aztec.spans.AztecURLSpan;
import org.wordpress.aztec.spans.AztecUnderlineSpan;
import org.wordpress.aztec.spans.C5154b;
import org.wordpress.aztec.spans.C5155c;
import org.wordpress.aztec.spans.C5171t;
import org.wordpress.aztec.spans.C5173v;
import org.wordpress.aztec.spans.C5174w;
import org.wordpress.aztec.spans.HighlightSpan;
import org.wordpress.aztec.spans.S;
import org.wordpress.aztec.spans.X;
import org.xml.sax.Attributes;
import org.xml.sax.ContentHandler;
import org.xml.sax.Locator;
import org.xml.sax.ext.LexicalHandler;

/* loaded from: classes3.dex */
public final class F implements ContentHandler, LexicalHandler {
    public int a;
    public int b;
    public E c;
    public boolean d;
    public boolean e;
    public List f;
    public SpannableStringBuilder g;
    public com.quizlet.data.repository.explanations.question.a h;
    public Context i;
    public List j;
    public boolean k;

    public static void a(SpannableStringBuilder spannableStringBuilder, x xVar) {
        org.wordpress.aztec.spans.C c;
        int iOrdinal = xVar.ordinal();
        if (iOrdinal == 21) {
            c = (AztecURLSpan) org.wordpress.aztec.util.b.d(spannableStringBuilder, AztecURLSpan.class);
        } else if (iOrdinal == 33) {
            c = (S) org.wordpress.aztec.util.b.d(spannableStringBuilder, S.class);
        } else if (iOrdinal != 34) {
            switch (iOrdinal) {
                case 10:
                    c = (AztecStyleBoldSpan) org.wordpress.aztec.util.b.d(spannableStringBuilder, AztecStyleBoldSpan.class);
                    break;
                case 11:
                    c = (AztecStyleStrongSpan) org.wordpress.aztec.util.b.d(spannableStringBuilder, AztecStyleStrongSpan.class);
                    break;
                case 12:
                    c = (AztecStyleItalicSpan) org.wordpress.aztec.util.b.d(spannableStringBuilder, AztecStyleItalicSpan.class);
                    break;
                case 13:
                    c = (AztecStyleEmphasisSpan) org.wordpress.aztec.util.b.d(spannableStringBuilder, AztecStyleEmphasisSpan.class);
                    break;
                case 14:
                    c = (AztecStyleCiteSpan) org.wordpress.aztec.util.b.d(spannableStringBuilder, AztecStyleCiteSpan.class);
                    break;
                case 15:
                    c = (AztecUnderlineSpan) org.wordpress.aztec.util.b.d(spannableStringBuilder, AztecUnderlineSpan.class);
                    break;
                default:
                    switch (iOrdinal) {
                        case EventType.SUBS /* 25 */:
                            c = (AztecRelativeSizeBigSpan) org.wordpress.aztec.util.b.d(spannableStringBuilder, AztecRelativeSizeBigSpan.class);
                            break;
                        case EventType.CDN /* 26 */:
                            c = (AztecRelativeSizeSmallSpan) org.wordpress.aztec.util.b.d(spannableStringBuilder, AztecRelativeSizeSmallSpan.class);
                            break;
                        case 27:
                            c = (AztecSuperscriptSpan) org.wordpress.aztec.util.b.d(spannableStringBuilder, AztecSuperscriptSpan.class);
                            break;
                        case 28:
                            c = (AztecSubscriptSpan) org.wordpress.aztec.util.b.d(spannableStringBuilder, AztecSubscriptSpan.class);
                            break;
                        case 29:
                            c = (C5173v) org.wordpress.aztec.util.b.d(spannableStringBuilder, C5173v.class);
                            break;
                        case 30:
                            c = (AztecTypefaceMonospaceSpan) org.wordpress.aztec.util.b.d(spannableStringBuilder, AztecTypefaceMonospaceSpan.class);
                            break;
                        case 31:
                            c = (C5154b) org.wordpress.aztec.util.b.d(spannableStringBuilder, C5154b.class);
                            break;
                        default:
                            throw new IllegalArgumentException("Style not supported");
                    }
            }
        } else {
            c = (HighlightSpan) org.wordpress.aztec.util.b.d(spannableStringBuilder, HighlightSpan.class);
        }
        int spanStart = spannableStringBuilder.getSpanStart(c);
        spannableStringBuilder.setSpan(c, spanStart, spannableStringBuilder.length(), 33);
        c.h(spannableStringBuilder, spanStart, spannableStringBuilder.length());
    }

    public static void b(SpannableStringBuilder spannableStringBuilder) {
        int length = spannableStringBuilder.length();
        Object[] spans = spannableStringBuilder.getSpans(length, length, E.class);
        if (spans.length > 0) {
            length = spannableStringBuilder.getSpanStart(spans[0]);
        }
        spannableStringBuilder.setSpan(new C5155c(), length, length, 17);
    }

    public final void c(SpannableStringBuilder spannableStringBuilder, x xVar, Attributes attributes) {
        Object aztecURLSpan;
        C5146b attributes2 = new C5146b(attributes);
        int iOrdinal = xVar.ordinal();
        if (iOrdinal == 21) {
            aztecURLSpan = new AztecURLSpan(attributes2.a("href") ? attributes2.getValue("href") : "", attributes2);
        } else if (iOrdinal == 33) {
            aztecURLSpan = new S(attributes2);
        } else if (iOrdinal != 34) {
            switch (iOrdinal) {
                case 10:
                    aztecURLSpan = new AztecStyleBoldSpan(attributes2);
                    break;
                case 11:
                    aztecURLSpan = new AztecStyleStrongSpan(attributes2);
                    break;
                case 12:
                    aztecURLSpan = new AztecStyleItalicSpan(attributes2);
                    break;
                case 13:
                    aztecURLSpan = new AztecStyleEmphasisSpan(attributes2);
                    break;
                case 14:
                    aztecURLSpan = new AztecStyleCiteSpan(attributes2);
                    break;
                case 15:
                    aztecURLSpan = new AztecUnderlineSpan(attributes2);
                    break;
                default:
                    switch (iOrdinal) {
                        case EventType.SUBS /* 25 */:
                            Intrinsics.checkNotNullParameter(attributes2, "attributes");
                            aztecURLSpan = new AztecRelativeSizeBigSpan("big", 1.25f, attributes2);
                            break;
                        case EventType.CDN /* 26 */:
                            Intrinsics.checkNotNullParameter(attributes2, "attributes");
                            aztecURLSpan = new AztecRelativeSizeSmallSpan("small", 0.8f, attributes2);
                            break;
                        case 27:
                            aztecURLSpan = new AztecSuperscriptSpan(attributes2);
                            break;
                        case 28:
                            aztecURLSpan = new AztecSubscriptSpan(attributes2);
                            break;
                        case 29:
                            Intrinsics.checkNotNullParameter(attributes2, "attributes");
                            C5173v c5173v = new C5173v();
                            c5173v.a = attributes2;
                            c5173v.b = "font";
                            aztecURLSpan = c5173v;
                            break;
                        case 30:
                            Intrinsics.checkNotNullParameter(attributes2, "attributes");
                            aztecURLSpan = new AztecTypefaceMonospaceSpan(attributes2);
                            break;
                        case 31:
                            aztecURLSpan = new C5154b(attributes2);
                            break;
                        default:
                            throw new IllegalArgumentException("Style not supported");
                    }
            }
        } else {
            int i = HighlightSpan.c;
            Intrinsics.checkNotNullParameter(attributes2, "attributes");
            Context context = this.i;
            Intrinsics.checkNotNullParameter(context, "context");
            aztecURLSpan = C5174w.a(attributes2, context, null, 4);
        }
        int length = spannableStringBuilder.length();
        spannableStringBuilder.setSpan(aztecURLSpan, length, length, 17);
    }

    @Override // org.xml.sax.ContentHandler
    public final void characters(char[] cArr, int i, int i2) {
        SpannableStringBuilder spannableStringBuilder;
        char cCharAt;
        int i3 = 0;
        if (this.b != 0) {
            while (i3 < i2) {
                this.c.a.append(cArr[i3 + i]);
                i3++;
            }
            return;
        }
        StringBuilder sb = new StringBuilder();
        while (true) {
            spannableStringBuilder = this.g;
            if (i3 >= i2) {
                break;
            }
            char c = cArr[i3 + i];
            if ((this.d || this.e || c != ' ') && c != '\n') {
                sb.append(c);
            } else if (c != ' ' || this.k) {
                int length = sb.length();
                if (length == 0) {
                    int length2 = spannableStringBuilder.length();
                    cCharAt = length2 == 0 ? '\n' : spannableStringBuilder.charAt(length2 - 1);
                } else {
                    cCharAt = sb.charAt(length - 1);
                }
                if (cCharAt != ' ' && cCharAt != '\n') {
                    sb.append(' ');
                }
            } else {
                sb.append(c);
            }
            i3++;
        }
        List list = this.f;
        if (list != null) {
            Iterator it2 = list.iterator();
            while (it2.hasNext()) {
                if (it2.next() != null) {
                    throw new ClassCastException();
                }
            }
        }
        spannableStringBuilder.append((CharSequence) sb);
    }

    @Override // org.xml.sax.ext.LexicalHandler
    public final void comment(char[] cArr, int i, int i2) {
        if (this.b != 0) {
            this.c.a.append("<!--");
            for (int i3 = 0; i3 < i2; i3++) {
                this.c.a.append(cArr[i3 + i]);
            }
            this.c.a.append("-->");
            return;
        }
        String str = new String(cArr, i, i2);
        SpannableStringBuilder spannableStringBuilder = this.g;
        int length = spannableStringBuilder.length();
        List list = this.f;
        if (list != null) {
            Iterator it2 = list.iterator();
            while (it2.hasNext()) {
                if (it2.next() != null) {
                    throw new ClassCastException();
                }
            }
        }
        spannableStringBuilder.append((CharSequence) str);
        spannableStringBuilder.setSpan(new C5171t(str), length, spannableStringBuilder.length(), 33);
    }

    @Override // org.xml.sax.ext.LexicalHandler
    public final void endCDATA() {
    }

    @Override // org.xml.sax.ext.LexicalHandler
    public final void endDTD() {
    }

    @Override // org.xml.sax.ContentHandler
    public final void endDocument() {
    }

    /* JADX WARN: Removed duplicated region for block: B:29:0x00bc  */
    @Override // org.xml.sax.ContentHandler
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void endElement(java.lang.String r17, java.lang.String r18, java.lang.String r19) {
        /*
            Method dump skipped, instructions count: 566
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: org.wordpress.aztec.F.endElement(java.lang.String, java.lang.String, java.lang.String):void");
    }

    @Override // org.xml.sax.ext.LexicalHandler
    public final void endEntity(String str) {
    }

    @Override // org.xml.sax.ContentHandler
    public final void endPrefixMapping(String str) {
    }

    @Override // org.xml.sax.ContentHandler
    public final void ignorableWhitespace(char[] cArr, int i, int i2) {
    }

    @Override // org.xml.sax.ContentHandler
    public final void processingInstruction(String str, String str2) {
    }

    @Override // org.xml.sax.ContentHandler
    public final void setDocumentLocator(Locator locator) {
    }

    @Override // org.xml.sax.ContentHandler
    public final void skippedEntity(String str) {
    }

    @Override // org.xml.sax.ext.LexicalHandler
    public final void startCDATA() {
    }

    @Override // org.xml.sax.ext.LexicalHandler
    public final void startDTD(String str, String str2, String str3) {
    }

    @Override // org.xml.sax.ContentHandler
    public final void startDocument() {
    }

    @Override // org.xml.sax.ContentHandler
    public final void startElement(String str, String str2, String str3, Attributes attributes) {
        String str4;
        Attributes attributes2;
        if (this.j.contains(str2)) {
            return;
        }
        int i = this.a + 1;
        this.a = i;
        int i2 = this.b;
        SpannableStringBuilder spannableStringBuilder = this.g;
        if (i2 != 0) {
            if (str2.equalsIgnoreCase("aztec_cursor")) {
                b(spannableStringBuilder);
                return;
            }
            StringBuilder sb = this.c.a;
            sb.append('<');
            sb.append(str2);
            sb.append((CharSequence) D2.b(attributes));
            sb.append('>');
            this.b++;
            return;
        }
        Iterator it2 = this.f.iterator();
        while (it2.hasNext()) {
            if (it2.next() != null) {
                throw new ClassCastException();
            }
        }
        com.quizlet.data.repository.explanations.question.a aVar = this.h;
        if (aVar != null) {
            if (str2.equalsIgnoreCase("pre")) {
                this.d = true;
            }
            str4 = str2;
            attributes2 = attributes;
            if (aVar.g(true, str4, spannableStringBuilder, this.i, attributes2, i)) {
                return;
            }
        } else {
            str4 = str2;
            attributes2 = attributes;
        }
        if (str4.equalsIgnoreCase("br")) {
            return;
        }
        if (str4.equalsIgnoreCase("aztec_cursor")) {
            b(spannableStringBuilder);
            return;
        }
        if (str4.equalsIgnoreCase("strong")) {
            c(spannableStringBuilder, x.l, attributes2);
            return;
        }
        if (str4.equalsIgnoreCase("b")) {
            c(spannableStringBuilder, x.k, attributes2);
            return;
        }
        if (str4.equalsIgnoreCase("em")) {
            c(spannableStringBuilder, x.n, attributes2);
            return;
        }
        if (str4.equalsIgnoreCase("cite")) {
            c(spannableStringBuilder, x.o, attributes2);
            return;
        }
        if (str4.equalsIgnoreCase("dfn")) {
            c(spannableStringBuilder, x.m, attributes2);
            return;
        }
        if (str4.equalsIgnoreCase("i")) {
            c(spannableStringBuilder, x.m, attributes2);
            return;
        }
        if (str4.equalsIgnoreCase("big")) {
            c(spannableStringBuilder, x.z, attributes2);
            return;
        }
        if (str4.equalsIgnoreCase("small")) {
            c(spannableStringBuilder, x.A, attributes2);
            return;
        }
        if (str4.equalsIgnoreCase("font")) {
            c(spannableStringBuilder, x.D, attributes2);
            return;
        }
        if (str4.equalsIgnoreCase("tt")) {
            c(spannableStringBuilder, x.E, attributes2);
            return;
        }
        if (str4.equalsIgnoreCase("a")) {
            c(spannableStringBuilder, x.v, attributes2);
            return;
        }
        if (str4.equalsIgnoreCase("u")) {
            c(spannableStringBuilder, x.p, attributes2);
            return;
        }
        if (str4.equalsIgnoreCase("sup")) {
            c(spannableStringBuilder, x.B, attributes2);
            return;
        }
        if (str4.equalsIgnoreCase("sub")) {
            c(spannableStringBuilder, x.C, attributes2);
            return;
        }
        if (str4.equalsIgnoreCase("code")) {
            this.e = true;
            c(spannableStringBuilder, x.F, attributes2);
            return;
        }
        if (str4.equalsIgnoreCase("mark")) {
            c(spannableStringBuilder, x.H, attributes2);
            return;
        }
        if (str4.equalsIgnoreCase("highlight")) {
            c(spannableStringBuilder, x.I, attributes2);
            return;
        }
        if (X.d.contains(str4.toLowerCase()) || this.b != 0) {
            return;
        }
        this.b = 1;
        E e = new E();
        this.c = e;
        e.a = new StringBuilder();
        StringBuilder sb2 = this.c.a;
        sb2.append('<');
        sb2.append(str4);
        sb2.append((CharSequence) D2.b(attributes2));
        sb2.append('>');
        SpannableStringBuilder spannableStringBuilder2 = this.g;
        spannableStringBuilder2.setSpan(this.c, spannableStringBuilder2.length(), spannableStringBuilder2.length(), 17);
    }

    @Override // org.xml.sax.ext.LexicalHandler
    public final void startEntity(String str) {
    }

    @Override // org.xml.sax.ContentHandler
    public final void startPrefixMapping(String str, String str2) {
    }
}
