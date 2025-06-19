package androidx.navigation;

import android.net.Uri;
import android.os.Bundle;
import androidx.compose.animation.d0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3335e2;
import com.google.android.gms.internal.mlkit_vision_camera.E1;
import com.google.android.gms.internal.mlkit_vision_camera.K1;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Regex;
import kotlin.text.StringsKt;

/* loaded from: classes.dex */
public abstract class B {
    public static final /* synthetic */ int e = 0;
    public final String a;
    public final androidx.navigation.internal.m b;
    public D c;
    public final androidx.collection.W d;

    static {
        new LinkedHashMap();
    }

    public B(W navigator) {
        Intrinsics.checkNotNullParameter(navigator, "navigator");
        LinkedHashMap linkedHashMap = X.b;
        String navigatorName = K1.h(navigator.getClass());
        Intrinsics.checkNotNullParameter(navigatorName, "navigatorName");
        this.a = navigatorName;
        this.b = new androidx.navigation.internal.m(this);
        this.d = new androidx.collection.W(0);
    }

    public final void a(C1301x navDeepLink) {
        Intrinsics.checkNotNullParameter(navDeepLink, "navDeepLink");
        androidx.navigation.internal.m mVar = this.b;
        mVar.getClass();
        Intrinsics.checkNotNullParameter(navDeepLink, "navDeepLink");
        ArrayList arrayListB = E1.b((LinkedHashMap) mVar.e, new androidx.navigation.internal.k(navDeepLink, 0));
        if (arrayListB.isEmpty()) {
            ((ArrayList) mVar.b).add(navDeepLink);
            return;
        }
        throw new IllegalArgumentException(("Deep link " + navDeepLink.a + " can't be used to open destination " + ((B) mVar.d) + ".\nFollowing required arguments are missing: " + arrayListB).toString());
    }

    public final Bundle b(Bundle from) {
        Object obj;
        LinkedHashMap linkedHashMap = (LinkedHashMap) this.b.e;
        if (from == null && linkedHashMap.isEmpty()) {
            return null;
        }
        kotlin.collections.V.c();
        Bundle source = AbstractC3206m6.a((Pair[]) Arrays.copyOf(new Pair[0], 0));
        Intrinsics.checkNotNullParameter(source, "source");
        for (Map.Entry entry : linkedHashMap.entrySet()) {
            String name = (String) entry.getKey();
            C1289k c1289k = (C1289k) entry.getValue();
            c1289k.getClass();
            Intrinsics.checkNotNullParameter(name, "name");
            Intrinsics.checkNotNullParameter(source, "bundle");
            if (c1289k.c && (obj = c1289k.e) != null) {
                c1289k.a.e(source, name, obj);
            }
        }
        if (from != null) {
            Intrinsics.checkNotNullParameter(source, "source");
            Intrinsics.checkNotNullParameter(from, "from");
            source.putAll(from);
            for (Map.Entry entry2 : linkedHashMap.entrySet()) {
                String name2 = (String) entry2.getKey();
                C1289k c1289k2 = (C1289k) entry2.getValue();
                if (!c1289k2.d) {
                    Intrinsics.checkNotNullParameter(name2, "name");
                    Intrinsics.checkNotNullParameter(source, "bundle");
                    S s = c1289k2.a;
                    if (!c1289k2.b) {
                        Intrinsics.checkNotNullParameter(source, "source");
                        if (!AbstractC3335e2.a(source, name2) || !AbstractC3335e2.k(source, name2)) {
                        }
                        StringBuilder sbY = android.support.v4.media.session.a.y("Wrong argument type for '", name2, "' in argument savedState. ");
                        sbY.append(s.b());
                        sbY.append(" expected.");
                        throw new IllegalArgumentException(sbY.toString().toString());
                    }
                    try {
                        s.a(source, name2);
                    } catch (IllegalStateException unused) {
                    }
                }
            }
        }
        return source;
    }

    /* JADX WARN: Removed duplicated region for block: B:12:0x0025  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int[] e(androidx.navigation.B r7) {
        /*
            r6 = this;
            kotlin.collections.s r0 = new kotlin.collections.s
            r0.<init>()
            r1 = r6
        L6:
            androidx.navigation.D r2 = r1.c
            if (r7 == 0) goto Ld
            androidx.navigation.D r3 = r7.c
            goto Le
        Ld:
            r3 = 0
        Le:
            androidx.navigation.internal.m r4 = r1.b
            if (r3 == 0) goto L25
            androidx.navigation.D r3 = r7.c
            kotlin.jvm.internal.Intrinsics.d(r3)
            int r5 = r4.c
            androidx.camera.camera2.internal.concurrent.a r3 = r3.f
            androidx.navigation.B r3 = r3.s(r5)
            if (r3 != r1) goto L25
            r0.addFirst(r1)
            goto L3b
        L25:
            if (r2 == 0) goto L2f
            androidx.camera.camera2.internal.concurrent.a r3 = r2.f
            int r3 = r3.b
            int r4 = r4.c
            if (r3 == r4) goto L32
        L2f:
            r0.addFirst(r1)
        L32:
            boolean r1 = kotlin.jvm.internal.Intrinsics.b(r2, r7)
            if (r1 == 0) goto L39
            goto L3b
        L39:
            if (r2 != 0) goto L6b
        L3b:
            java.util.List r7 = kotlin.collections.CollectionsKt.w0(r0)
            java.util.ArrayList r0 = new java.util.ArrayList
            r1 = 10
            int r1 = kotlin.collections.C.q(r7, r1)
            r0.<init>(r1)
            java.util.Iterator r7 = r7.iterator()
        L4e:
            boolean r1 = r7.hasNext()
            if (r1 == 0) goto L66
            java.lang.Object r1 = r7.next()
            androidx.navigation.B r1 = (androidx.navigation.B) r1
            androidx.navigation.internal.m r1 = r1.b
            int r1 = r1.c
            java.lang.Integer r1 = java.lang.Integer.valueOf(r1)
            r0.add(r1)
            goto L4e
        L66:
            int[] r7 = kotlin.collections.CollectionsKt.v0(r0)
            return r7
        L6b:
            r1 = r2
            goto L6
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.navigation.B.e(androidx.navigation.B):int[]");
    }

    /* JADX WARN: Removed duplicated region for block: B:22:0x0074  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x00c7  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean equals(java.lang.Object r12) {
        /*
            r11 = this;
            r0 = 1
            if (r11 != r12) goto L5
            goto Ldb
        L5:
            r1 = 0
            if (r12 == 0) goto Ldc
            boolean r2 = r12 instanceof androidx.navigation.B
            if (r2 != 0) goto Le
            goto Ldc
        Le:
            androidx.navigation.internal.m r2 = r11.b
            java.io.Serializable r3 = r2.b
            java.util.ArrayList r3 = (java.util.ArrayList) r3
            androidx.navigation.B r12 = (androidx.navigation.B) r12
            androidx.navigation.internal.m r4 = r12.b
            java.io.Serializable r5 = r4.b
            java.util.ArrayList r5 = (java.util.ArrayList) r5
            boolean r3 = kotlin.jvm.internal.Intrinsics.b(r3, r5)
            androidx.collection.W r5 = r11.d
            int r6 = r5.g()
            androidx.collection.W r7 = r12.d
            int r8 = r7.g()
            java.lang.String r9 = "<this>"
            if (r6 != r8) goto L61
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r5, r9)
            androidx.collection.X r6 = new androidx.collection.X
            r6.<init>(r5)
            kotlin.sequences.a r6 = kotlin.sequences.n.b(r6)
            java.util.Iterator r6 = r6.iterator()
        L40:
            boolean r8 = r6.hasNext()
            if (r8 == 0) goto L5f
            java.lang.Object r8 = r6.next()
            java.lang.Number r8 = (java.lang.Number) r8
            int r8 = r8.intValue()
            java.lang.Object r10 = r5.d(r8)
            java.lang.Object r8 = r7.d(r8)
            boolean r8 = kotlin.jvm.internal.Intrinsics.b(r10, r8)
            if (r8 != 0) goto L40
            goto L61
        L5f:
            r5 = r0
            goto L62
        L61:
            r5 = r1
        L62:
            java.util.Map r6 = r11.h()
            int r6 = r6.size()
            java.util.Map r7 = r12.h()
            int r7 = r7.size()
            if (r6 != r7) goto Lc0
            java.util.Map r6 = r11.h()
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r9)
            java.util.Set r6 = r6.entrySet()
            java.lang.Iterable r6 = (java.lang.Iterable) r6
            kotlin.collections.w r6 = kotlin.collections.CollectionsKt.D(r6)
            java.lang.Object r6 = r6.b
            java.lang.Iterable r6 = (java.lang.Iterable) r6
            java.util.Iterator r6 = r6.iterator()
        L8d:
            boolean r7 = r6.hasNext()
            if (r7 == 0) goto Lbe
            java.lang.Object r7 = r6.next()
            java.util.Map$Entry r7 = (java.util.Map.Entry) r7
            java.util.Map r8 = r12.h()
            java.lang.Object r9 = r7.getKey()
            boolean r8 = r8.containsKey(r9)
            if (r8 == 0) goto Lc0
            java.util.Map r8 = r12.h()
            java.lang.Object r9 = r7.getKey()
            java.lang.Object r8 = r8.get(r9)
            java.lang.Object r7 = r7.getValue()
            boolean r7 = kotlin.jvm.internal.Intrinsics.b(r8, r7)
            if (r7 == 0) goto Lc0
            goto L8d
        Lbe:
            r12 = r0
            goto Lc1
        Lc0:
            r12 = r1
        Lc1:
            int r6 = r2.c
            int r7 = r4.c
            if (r6 != r7) goto Ldc
            java.lang.Object r2 = r2.f
            java.lang.String r2 = (java.lang.String) r2
            java.lang.Object r4 = r4.f
            java.lang.String r4 = (java.lang.String) r4
            boolean r2 = kotlin.jvm.internal.Intrinsics.b(r2, r4)
            if (r2 == 0) goto Ldc
            if (r3 == 0) goto Ldc
            if (r5 == 0) goto Ldc
            if (r12 == 0) goto Ldc
        Ldb:
            return r0
        Ldc:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.navigation.B.equals(java.lang.Object):boolean");
    }

    public final void g(int i) {
        androidx.collection.W w = this.d;
        if (w.g() != 0 && w.d(i) != null) {
            throw new ClassCastException();
        }
        D d = this.c;
        if (d != null) {
            d.g(i);
        }
    }

    public final Map h() {
        return kotlin.collections.V.l((LinkedHashMap) this.b.e);
    }

    public int hashCode() {
        androidx.navigation.internal.m mVar = this.b;
        int i = mVar.c * 31;
        String str = (String) mVar.f;
        int iHashCode = i + (str != null ? str.hashCode() : 0);
        Iterator it2 = ((ArrayList) mVar.b).iterator();
        while (it2.hasNext()) {
            int i2 = iHashCode * 31;
            String str2 = ((C1301x) it2.next()).a;
            iHashCode = (i2 + (str2 != null ? str2.hashCode() : 0)) * 961;
        }
        androidx.collection.W w = this.d;
        Intrinsics.checkNotNullParameter(w, "<this>");
        if (w.g() > 0) {
            w.h(0).getClass();
            throw new ClassCastException();
        }
        for (String str3 : h().keySet()) {
            int iE = d0.e(iHashCode * 31, 31, str3);
            Object obj = h().get(str3);
            iHashCode = iE + (obj != null ? obj.hashCode() : 0);
        }
        return iHashCode;
    }

    public A i(com.quizlet.data.repository.set.f deepLinkRequest) {
        boolean zE;
        Regex regex;
        kotlin.text.m mVarD;
        Intrinsics.checkNotNullParameter(deepLinkRequest, "navDeepLinkRequest");
        androidx.navigation.internal.m mVar = this.b;
        mVar.getClass();
        Intrinsics.checkNotNullParameter(deepLinkRequest, "navDeepLinkRequest");
        ArrayList arrayList = (ArrayList) mVar.b;
        if (arrayList.isEmpty()) {
            return null;
        }
        Iterator it2 = arrayList.iterator();
        A a = null;
        while (it2.hasNext()) {
            C1301x c1301x = (C1301x) it2.next();
            c1301x.getClass();
            Intrinsics.checkNotNullParameter(deepLinkRequest, "deepLinkRequest");
            kotlin.u uVar = c1301x.d;
            Regex regex2 = (Regex) uVar.getValue();
            Uri uri = (Uri) deepLinkRequest.b;
            if (regex2 == null) {
                zE = true;
            } else if (uri == null) {
                zE = false;
            } else {
                Regex regex3 = (Regex) uVar.getValue();
                Intrinsics.d(regex3);
                zE = regex3.e(uri.toString());
            }
            if (zE) {
                LinkedHashMap arguments = (LinkedHashMap) mVar.e;
                Bundle bundleD = uri != null ? c1301x.d(uri, arguments) : null;
                int iB = c1301x.b(uri);
                String str = (String) deepLinkRequest.c;
                boolean z = str != null && str.equals(null);
                String mimeType = (String) deepLinkRequest.d;
                if (mimeType != null) {
                    Intrinsics.checkNotNullParameter(mimeType, "mimeType");
                }
                if (bundleD == null) {
                    if (z) {
                        Intrinsics.checkNotNullParameter(arguments, "arguments");
                        kotlin.collections.V.c();
                        Bundle source = AbstractC3206m6.a((Pair[]) Arrays.copyOf(new Pair[0], 0));
                        Intrinsics.checkNotNullParameter(source, "source");
                        if (uri != null && (regex = (Regex) uVar.getValue()) != null && (mVarD = regex.d(uri.toString())) != null) {
                            c1301x.e(mVarD, source, arguments);
                            if (((Boolean) c1301x.e.getValue()).booleanValue()) {
                                c1301x.f(uri, source, arguments);
                            }
                        }
                        if (E1.b(arguments, new C1299v(source, 1)).isEmpty()) {
                        }
                    }
                }
                A a2 = new A((B) mVar.d, bundleD, c1301x.l, iB, z);
                if (a == null || a2.compareTo(a) > 0) {
                    a = a2;
                }
            }
        }
        return a;
    }

    public final void j(String str) {
        androidx.navigation.internal.m mVar = this.b;
        if (str == null) {
            mVar.c = 0;
        } else {
            mVar.getClass();
            if (StringsKt.O(str)) {
                throw new IllegalArgumentException("Cannot have an empty route");
            }
            String uriPattern = "android-app://androidx.navigation/".concat(str);
            Intrinsics.checkNotNullParameter(uriPattern, "uriPattern");
            ArrayList arrayListB = E1.b((LinkedHashMap) mVar.e, new androidx.navigation.internal.k(new C1301x(uriPattern), 1));
            if (!arrayListB.isEmpty()) {
                StringBuilder sbY = android.support.v4.media.session.a.y("Cannot set route \"", str, "\" for destination ");
                sbY.append((B) mVar.d);
                sbY.append(". Following required arguments are missing: ");
                sbY.append(arrayListB);
                throw new IllegalArgumentException(sbY.toString().toString());
            }
            mVar.g = kotlin.l.b(new androidx.navigation.internal.l(uriPattern, 0));
            mVar.c = uriPattern.hashCode();
        }
        mVar.f = str;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(getClass().getSimpleName());
        sb.append("(0x");
        androidx.navigation.internal.m mVar = this.b;
        mVar.getClass();
        sb.append(Integer.toHexString(mVar.c));
        sb.append(")");
        String str = (String) mVar.f;
        if (str != null && !StringsKt.O(str)) {
            sb.append(" route=");
            sb.append((String) mVar.f);
        }
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        return string;
    }
}
