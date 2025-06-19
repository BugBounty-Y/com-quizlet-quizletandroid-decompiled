package com.quizlet.quizletandroid.deeplinks;

import androidx.recyclerview.widget.C1372j;
import com.amazon.device.ads.DtbConstants;
import com.braze.managers.U;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3705q4;
import com.quizlet.quizletandroid.config.features.properties.d;
import com.quizlet.quizletandroid.managers.deeplinks.A;
import com.quizlet.quizletandroid.managers.deeplinks.n;
import com.quizlet.quizletandroid.managers.deeplinks.z;
import java.util.List;
import java.util.NoSuchElementException;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.D;
import kotlin.text.StringsKt;
import okhttp3.s;
import timber.log.c;

/* loaded from: classes3.dex */
public final class a {
    public static final a a = new a();

    /* JADX WARN: Removed duplicated region for block: B:18:0x0049  */
    /* JADX WARN: Removed duplicated region for block: B:6:0x0012  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.lang.Double b(java.lang.String r6) {
        /*
            okhttp3.s r6 = c(r6)
            r0 = 0
            if (r6 == 0) goto L6d
            java.lang.String r1 = "sc"
            java.lang.String r2 = "name"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r1, r2)
            java.util.ArrayList r6 = r6.g
            if (r6 != 0) goto L14
        L12:
            r6 = r0
            goto L47
        L14:
            r2 = 0
            int r3 = r6.size()
            kotlin.ranges.IntRange r2 = kotlin.ranges.l.h(r2, r3)
            r3 = 2
            kotlin.ranges.h r2 = kotlin.ranges.l.g(r3, r2)
            int r3 = r2.a
            int r4 = r2.b
            int r2 = r2.c
            if (r2 <= 0) goto L2c
            if (r3 <= r4) goto L30
        L2c:
            if (r2 >= 0) goto L12
            if (r4 > r3) goto L12
        L30:
            java.lang.Object r5 = r6.get(r3)
            boolean r5 = r1.equals(r5)
            if (r5 == 0) goto L43
            int r3 = r3 + 1
            java.lang.Object r6 = r6.get(r3)
            java.lang.String r6 = (java.lang.String) r6
            goto L47
        L43:
            if (r3 == r4) goto L12
            int r3 = r3 + r2
            goto L30
        L47:
            if (r6 == 0) goto L6d
            java.lang.String r1 = "encodedNum"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r1)
            r1 = 36
            int r1 = kotlin.text.CharsKt.checkRadix(r1)
            long r1 = java.lang.Long.parseLong(r6, r1)
            r3 = 199(0xc7, double:9.83E-322)
            long r1 = r1 / r3
            int r6 = (int) r1
            double r1 = (double) r6
            r6 = 10
            double r3 = (double) r6
            double r1 = r1 / r3
            r3 = 0
            int r6 = (r1 > r3 ? 1 : (r1 == r3 ? 0 : -1))
            if (r6 != 0) goto L68
            goto L6d
        L68:
            java.lang.Double r6 = java.lang.Double.valueOf(r1)
            return r6
        L6d:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.deeplinks.a.b(java.lang.String):java.lang.Double");
    }

    public static s c(String str) {
        if (StringsKt.G(str, "quizlet://", true)) {
            str = D.o(str, "quizlet://", DtbConstants.HTTPS, true);
        }
        Intrinsics.checkNotNullParameter(str, "<this>");
        try {
            Intrinsics.checkNotNullParameter(str, "<this>");
            C1372j c1372j = new C1372j();
            c1372j.l(null, str);
            return c1372j.d();
        } catch (IllegalArgumentException unused) {
            return null;
        }
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Code restructure failed: missing block: B:17:0x002e, code lost:
    
        if (r3.equals("match") == false) goto L49;
     */
    /* JADX WARN: Code restructure failed: missing block: B:20:0x0033, code lost:
    
        return com.quizlet.generated.enums.A1.MOBILE_SCATTER;
     */
    /* JADX WARN: Code restructure failed: missing block: B:27:0x0046, code lost:
    
        if (r3.equals("cards") == false) goto L49;
     */
    /* JADX WARN: Code restructure failed: missing block: B:40:0x0067, code lost:
    
        if (r3.equals("flashcards") == false) goto L49;
     */
    /* JADX WARN: Code restructure failed: missing block: B:48:0x007c, code lost:
    
        if (r3.equals("classic-cards") == false) goto L49;
     */
    /* JADX WARN: Code restructure failed: missing block: B:52:0x0092, code lost:
    
        return com.quizlet.generated.enums.A1.FLASHCARDS;
     */
    /* JADX WARN: Code restructure failed: missing block: B:6:0x000f, code lost:
    
        if (r3.equals("scatter") == false) goto L49;
     */
    /* JADX WARN: Code restructure failed: missing block: B:9:0x0019, code lost:
    
        if (r3.equals("microscatter") == false) goto L49;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.quizlet.generated.enums.A1 d(java.lang.String r3) {
        /*
            int r0 = r3.hashCode()
            switch(r0) {
                case -1596981656: goto L76;
                case -1386164858: goto L6a;
                case -1191613069: goto L61;
                case 3556498: goto L55;
                case 93819384: goto L49;
                case 94431075: goto L40;
                case 102846020: goto L34;
                case 103668165: goto L28;
                case 113399775: goto L1c;
                case 1407001466: goto L13;
                case 1911146174: goto L9;
                default: goto L7;
            }
        L7:
            goto L7e
        L9:
            java.lang.String r0 = "scatter"
            boolean r0 = r3.equals(r0)
            if (r0 != 0) goto L31
            goto L7e
        L13:
            java.lang.String r0 = "microscatter"
            boolean r0 = r3.equals(r0)
            if (r0 != 0) goto L31
            goto L7e
        L1c:
            java.lang.String r0 = "write"
            boolean r0 = r3.equals(r0)
            if (r0 != 0) goto L25
            goto L7e
        L25:
            com.quizlet.generated.enums.A1 r3 = com.quizlet.generated.enums.A1.MOBILE_WRITE
            return r3
        L28:
            java.lang.String r0 = "match"
            boolean r0 = r3.equals(r0)
            if (r0 != 0) goto L31
            goto L7e
        L31:
            com.quizlet.generated.enums.A1 r3 = com.quizlet.generated.enums.A1.MOBILE_SCATTER
            return r3
        L34:
            java.lang.String r0 = "learn"
            boolean r0 = r3.equals(r0)
            if (r0 != 0) goto L3d
            goto L7e
        L3d:
            com.quizlet.generated.enums.A1 r3 = com.quizlet.generated.enums.A1.LEARNING_ASSISTANT
            return r3
        L40:
            java.lang.String r0 = "cards"
            boolean r0 = r3.equals(r0)
            if (r0 != 0) goto L90
            goto L7e
        L49:
            java.lang.String r0 = "blast"
            boolean r0 = r3.equals(r0)
            if (r0 != 0) goto L52
            goto L7e
        L52:
            com.quizlet.generated.enums.A1 r3 = com.quizlet.generated.enums.A1.SINGLE_PLAYER_BLAST
            return r3
        L55:
            java.lang.String r0 = "test"
            boolean r0 = r3.equals(r0)
            if (r0 != 0) goto L5e
            goto L7e
        L5e:
            com.quizlet.generated.enums.A1 r3 = com.quizlet.generated.enums.A1.TEST
            return r3
        L61:
            java.lang.String r0 = "flashcards"
            boolean r0 = r3.equals(r0)
            if (r0 != 0) goto L90
            goto L7e
        L6a:
            java.lang.String r0 = "blocks"
            boolean r0 = r3.equals(r0)
            if (r0 != 0) goto L73
            goto L7e
        L73:
            com.quizlet.generated.enums.A1 r3 = com.quizlet.generated.enums.A1.BLOCKS
            return r3
        L76:
            java.lang.String r0 = "classic-cards"
            boolean r0 = r3.equals(r0)
            if (r0 != 0) goto L90
        L7e:
            timber.log.a r0 = timber.log.c.a
            java.lang.IllegalArgumentException r1 = new java.lang.IllegalArgumentException
            java.lang.String r2 = "Handling deep link for unrecognized mode: "
            java.lang.String r3 = r2.concat(r3)
            r1.<init>(r3)
            r0.p(r1)
            r3 = 0
            return r3
        L90:
            com.quizlet.generated.enums.A1 r3 = com.quizlet.generated.enums.A1.FLASHCARDS
            return r3
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.deeplinks.a.d(java.lang.String):com.quizlet.generated.enums.A1");
    }

    public static Object e(String str, Function0 function0, Function1 function1) {
        try {
            return function1.invoke((String) function0.invoke());
        } catch (IllegalArgumentException unused) {
            c.a.o(android.support.v4.media.session.a.B("Expected Explanations deep link identifier to be a UUID in (", str, ")"), new Object[0]);
            return null;
        } catch (IndexOutOfBoundsException unused2) {
            c.a.o(android.support.v4.media.session.a.B("Unsupported Explanations deep link (", str, ")"), new Object[0]);
            return null;
        } catch (NoSuchElementException unused3) {
            c.a.o(android.support.v4.media.session.a.B("Expected Explanations deep link identifier not found in (", str, ")"), new Object[0]);
            return null;
        }
    }

    public AbstractC3705q4 a(String url, List pathSegments, boolean z) {
        Intrinsics.checkNotNullParameter(url, "url");
        Intrinsics.checkNotNullParameter(pathSegments, "pathSegments");
        String str = (String) (1 < pathSegments.size() ? pathSegments.get(1) : "");
        if (str.length() == 0 || str.equals("home")) {
            return new com.quizlet.quizletandroid.managers.deeplinks.s(z);
        }
        if (!str.equals("textbook-solutions")) {
            if (str.equals("questions")) {
                return (n) e(url, new U(this, pathSegments, 6), new d(5));
            }
            c.a.o(android.support.v4.media.session.a.B("Unsupported Explanations deep link (", url, ")"), new Object[0]);
            return null;
        }
        if (pathSegments.size() == 3 || (pathSegments.size() == 4 && ((CharSequence) CollectionsKt.U(pathSegments)).length() == 0)) {
            return (A) e(url, new U(this, pathSegments, 7), new d(6));
        }
        if (pathSegments.size() >= 4) {
            return (z) e(url, new U(this, pathSegments, 8), new d(7));
        }
        c.a.o(android.support.v4.media.session.a.B("Unsupported Explanations textbook deep link (", url, ")"), new Object[0]);
        return null;
    }

    /* JADX WARN: Removed duplicated region for block: B:30:0x00a2  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public com.quizlet.data.interactor.course.e f(java.lang.String r8) {
        /*
            r7 = this;
            java.lang.String r0 = "uri"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r8, r0)
            okhttp3.s r0 = c(r8)
            r1 = 0
            if (r0 != 0) goto L1d
            timber.log.a r0 = timber.log.c.a
            java.lang.IllegalArgumentException r2 = new java.lang.IllegalArgumentException
            java.lang.String r3 = "Attempting to interpret deep link for non-URL: "
            java.lang.String r8 = r3.concat(r8)
            r2.<init>(r8)
            r0.p(r2)
            return r1
        L1d:
            java.util.ArrayList r2 = new java.util.ArrayList
            java.util.ArrayList r3 = r0.f
            r2.<init>(r3)
            int r3 = r2.size()
            r4 = 0
            if (r3 == 0) goto L51
            java.lang.Object r2 = r2.get(r4)
            java.lang.String r2 = (java.lang.String) r2
            int r2 = r2.length()
            r3 = 2
            if (r2 == r3) goto L39
            goto L51
        L39:
            androidx.recyclerview.widget.j r0 = r0.f()
            java.util.ArrayList r2 = r0.c
            r2.remove(r4)
            boolean r3 = r2.isEmpty()
            if (r3 == 0) goto L4d
            java.lang.String r3 = ""
            r2.add(r3)
        L4d:
            okhttp3.s r0 = r0.d()
        L51:
            java.util.ArrayList r0 = r0.f
            boolean r2 = r0.isEmpty()
            r3 = 1
            if (r2 != 0) goto La2
            java.lang.Object r2 = r0.get(r4)
            java.lang.CharSequence r2 = (java.lang.CharSequence) r2
            kotlin.text.Regex r5 = new kotlin.text.Regex
            java.lang.String r6 = "^[0-9]*$"
            r5.<init>(r6)
            boolean r2 = r5.e(r2)
            if (r2 == 0) goto La2
            java.lang.Object r2 = r0.get(r4)
            java.lang.String r2 = (java.lang.String) r2
            long r4 = java.lang.Long.parseLong(r2)     // Catch: java.lang.NumberFormatException -> Lfc
            int r2 = r0.size()
            if (r2 <= r3) goto L90
            java.util.HashSet r2 = com.quizlet.quizletandroid.util.links.StudyModeUrlFragment.a
            java.lang.Object r6 = r0.get(r3)
            boolean r2 = r2.contains(r6)
            if (r2 == 0) goto L90
            java.lang.Object r0 = r0.get(r3)
            java.lang.String r0 = (java.lang.String) r0
            goto L91
        L90:
            r0 = r1
        L91:
            if (r0 == 0) goto L97
            com.quizlet.generated.enums.A1 r1 = d(r0)
        L97:
            com.quizlet.data.interactor.course.e r0 = new com.quizlet.data.interactor.course.e
            java.lang.Double r8 = b(r8)
            r0.<init>(r4, r1, r8)
            r1 = r0
            goto Lfc
        La2:
            int r2 = r0.size()
            if (r2 <= r3) goto Lfc
            java.lang.Object r2 = r0.get(r3)
            java.lang.CharSequence r2 = (java.lang.CharSequence) r2
            kotlin.text.Regex r5 = new kotlin.text.Regex
            java.lang.String r6 = "^[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*$"
            r5.<init>(r6)
            boolean r2 = r5.e(r2)
            if (r2 == 0) goto Lfc
            java.lang.Object r2 = r0.get(r3)
            java.lang.CharSequence r2 = (java.lang.CharSequence) r2
            java.lang.String r3 = "-"
            java.lang.String[] r3 = new java.lang.String[]{r3}
            r5 = 6
            java.util.List r2 = kotlin.text.StringsKt.W(r2, r3, r4, r5)
            java.lang.Object r2 = kotlin.collections.CollectionsKt.U(r2)     // Catch: java.lang.NumberFormatException -> Lfc
            java.lang.String r2 = (java.lang.String) r2     // Catch: java.lang.NumberFormatException -> Lfc
            long r2 = java.lang.Long.parseLong(r2)     // Catch: java.lang.NumberFormatException -> Lfc
            boolean r5 = r0.isEmpty()
            if (r5 != 0) goto Lfc
            java.util.HashSet r5 = com.quizlet.quizletandroid.util.links.StudyModeUrlFragment.a
            java.lang.Object r6 = r0.get(r4)
            boolean r5 = r5.contains(r6)
            if (r5 != 0) goto Le9
            goto Lfc
        Le9:
            com.quizlet.data.interactor.course.e r1 = new com.quizlet.data.interactor.course.e
            java.lang.Object r0 = r0.get(r4)
            java.lang.String r0 = (java.lang.String) r0
            com.quizlet.generated.enums.A1 r0 = d(r0)
            java.lang.Double r8 = b(r8)
            r1.<init>(r2, r0, r8)
        Lfc:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.deeplinks.a.f(java.lang.String):com.quizlet.data.interactor.course.e");
    }
}
