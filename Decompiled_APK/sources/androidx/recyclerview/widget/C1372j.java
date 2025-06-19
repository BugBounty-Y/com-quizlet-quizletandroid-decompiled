package androidx.recyclerview.widget;

import android.util.Log;
import android.util.SparseArray;
import androidx.appcompat.widget.C0070a;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import java.io.Serializable;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.Iterator;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.recyclerview.widget.j, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1372j {
    public final /* synthetic */ int a;
    public int b;
    public final ArrayList c;
    public ArrayList d;
    public Object e;
    public Object f;
    public Serializable g;
    public Object h;
    public Object i;

    public C1372j(C1370i c1370i, C1368h c1368h) {
        this.a = 0;
        this.c = new ArrayList();
        this.g = new IdentityHashMap();
        this.d = new ArrayList();
        this.h = new C0070a();
        this.e = c1370i;
        if (c1368h.a) {
            com.android.billingclient.api.s sVar = new com.android.billingclient.api.s(5, (char) 0);
            sVar.c = new SparseArray();
            sVar.b = 0;
            this.f = sVar;
        } else {
            C1356b c1356b = new C1356b();
            c1356b.a = new SparseArray();
            this.f = c1356b;
        }
        this.b = 1;
        C1356b c1356b2 = new C1356b();
        c1356b2.a = new J0();
        this.i = c1356b2;
    }

    public boolean a(int i, AbstractC1361d0 abstractC1361d0) {
        ArrayList arrayList = this.d;
        if (i < 0 || i > arrayList.size()) {
            throw new IndexOutOfBoundsException("Index must be between 0 and " + arrayList.size() + ". Given:" + i);
        }
        if (this.b != 1) {
            AbstractC3242q6.c("All sub adapters must have stable ids when stable id mode is ISOLATED_STABLE_IDS or SHARED_STABLE_IDS", abstractC1361d0.hasStableIds());
        } else if (abstractC1361d0.hasStableIds()) {
            Log.w("ConcatAdapter", "Stable ids in the adapter will be ignored as the ConcatAdapter is configured not to have stable ids");
        }
        int iK = k(abstractC1361d0);
        if ((iK == -1 ? null : (X) arrayList.get(iK)) != null) {
            return false;
        }
        X x = new X(abstractC1361d0, this, (S0) this.f, (J0) ((C1356b) this.i).a);
        arrayList.add(i, x);
        Iterator it2 = this.c.iterator();
        while (it2.hasNext()) {
            RecyclerView recyclerView = (RecyclerView) ((WeakReference) it2.next()).get();
            if (recyclerView != null) {
                abstractC1361d0.onAttachedToRecyclerView(recyclerView);
            }
        }
        if (x.e > 0) {
            ((C1370i) this.e).notifyItemRangeInserted(f(x), x.e);
        }
        e();
        return true;
    }

    public void b(String pathSegments) {
        Intrinsics.checkNotNullParameter(pathSegments, "pathSegments");
        int i = 0;
        while (true) {
            int iG = okhttp3.internal.b.g(pathSegments, i, "/\\", pathSegments.length());
            String str = pathSegments;
            m(str, i, iG, iG < pathSegments.length(), false);
            i = iG + 1;
            if (i > str.length()) {
                return;
            } else {
                pathSegments = str;
            }
        }
    }

    public void c(String name, String str) {
        Intrinsics.checkNotNullParameter(name, "name");
        if (this.d == null) {
            this.d = new ArrayList();
        }
        ArrayList arrayList = this.d;
        Intrinsics.d(arrayList);
        arrayList.add(okhttp3.o.b(0, 0, 219, name, " !\"#$&'(),/:;<=>?@[]\\^`{|}~", false));
        ArrayList arrayList2 = this.d;
        Intrinsics.d(arrayList2);
        arrayList2.add(str != null ? okhttp3.o.b(0, 0, 219, str, " !\"#$&'(),/:;<=>?@[]\\^`{|}~", false) : null);
    }

    public okhttp3.s d() {
        ArrayList arrayList;
        String str = (String) this.e;
        if (str == null) {
            throw new IllegalStateException("scheme == null");
        }
        String strF = okhttp3.o.f(0, 0, (String) this.f, 7);
        String strF2 = okhttp3.o.f(0, 0, (String) this.g, 7);
        String str2 = (String) this.h;
        if (str2 == null) {
            throw new IllegalStateException("host == null");
        }
        int iG = g();
        ArrayList arrayList2 = this.c;
        ArrayList arrayList3 = new ArrayList(kotlin.collections.C.q(arrayList2, 10));
        Iterator it2 = arrayList2.iterator();
        while (it2.hasNext()) {
            arrayList3.add(okhttp3.o.f(0, 0, (String) it2.next(), 7));
        }
        ArrayList<String> arrayList4 = this.d;
        if (arrayList4 != null) {
            ArrayList arrayList5 = new ArrayList(kotlin.collections.C.q(arrayList4, 10));
            for (String str3 : arrayList4) {
                arrayList5.add(str3 != null ? okhttp3.o.f(0, 0, str3, 3) : null);
            }
            arrayList = arrayList5;
        } else {
            arrayList = null;
        }
        String str4 = (String) this.i;
        return new okhttp3.s(str, strF, strF2, str2, iG, arrayList3, arrayList, str4 != null ? okhttp3.o.f(0, 0, str4, 7) : null, toString());
    }

    public void e() {
        EnumC1359c0 enumC1359c0;
        Iterator it2 = this.d.iterator();
        while (true) {
            if (!it2.hasNext()) {
                enumC1359c0 = EnumC1359c0.a;
                break;
            }
            X x = (X) it2.next();
            EnumC1359c0 stateRestorationPolicy = x.c.getStateRestorationPolicy();
            enumC1359c0 = EnumC1359c0.c;
            if (stateRestorationPolicy == enumC1359c0 || (stateRestorationPolicy == EnumC1359c0.b && x.e == 0)) {
                break;
            }
        }
        C1370i c1370i = (C1370i) this.e;
        if (enumC1359c0 != c1370i.getStateRestorationPolicy()) {
            c1370i.g(enumC1359c0);
        }
    }

    public int f(X x) {
        X x2;
        Iterator it2 = this.d.iterator();
        int i = 0;
        while (it2.hasNext() && (x2 = (X) it2.next()) != x) {
            i += x2.e;
        }
        return i;
    }

    public int g() {
        int i = this.b;
        if (i != -1) {
            return i;
        }
        String scheme = (String) this.e;
        Intrinsics.d(scheme);
        Intrinsics.checkNotNullParameter(scheme, "scheme");
        if (Intrinsics.b(scheme, "http")) {
            return 80;
        }
        return Intrinsics.b(scheme, "https") ? 443 : -1;
    }

    public void h(String str) {
        String strB;
        this.d = (str == null || (strB = okhttp3.o.b(0, 0, 211, str, " \"'<>#", true)) == null) ? null : okhttp3.o.h(strB);
    }

    public C0070a i(int i) {
        C0070a c0070a = (C0070a) this.h;
        if (c0070a.b) {
            c0070a = new C0070a();
        } else {
            c0070a.b = true;
        }
        Iterator it2 = this.d.iterator();
        int i2 = i;
        while (true) {
            if (!it2.hasNext()) {
                break;
            }
            X x = (X) it2.next();
            int i3 = x.e;
            if (i3 > i2) {
                c0070a.c = x;
                c0070a.a = i2;
                break;
            }
            i2 -= i3;
        }
        if (((X) c0070a.c) != null) {
            return c0070a;
        }
        throw new IllegalArgumentException(android.support.v4.media.session.a.f(i, "Cannot find wrapper for "));
    }

    public X j(F0 f0) {
        X x = (X) ((IdentityHashMap) this.g).get(f0);
        if (x != null) {
            return x;
        }
        throw new IllegalStateException("Cannot find wrapper for " + f0 + ", seems like it is not bound by this adapter: " + this);
    }

    public int k(AbstractC1361d0 abstractC1361d0) {
        ArrayList arrayList = this.d;
        int size = arrayList.size();
        for (int i = 0; i < size; i++) {
            if (((X) arrayList.get(i)).c == abstractC1361d0) {
                return i;
            }
        }
        return -1;
    }

    /* JADX WARN: Removed duplicated region for block: B:39:0x007f  */
    /* JADX WARN: Removed duplicated region for block: B:71:0x012b  */
    /* JADX WARN: Unreachable blocks removed: 1, instructions: 1 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void l(okhttp3.s r23, java.lang.String r24) {
        /*
            Method dump skipped, instructions count: 848
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.C1372j.l(okhttp3.s, java.lang.String):void");
    }

    public void m(String str, int i, int i2, boolean z, boolean z2) {
        String strB = okhttp3.o.b(i, i2, 240, str, " \"<>^`{}|/\\?#", z2);
        if (Intrinsics.b(strB, ".") || kotlin.text.D.l(strB, "%2e", true)) {
            return;
        }
        boolean zB = Intrinsics.b(strB, "..");
        ArrayList arrayList = this.c;
        if (zB || kotlin.text.D.l(strB, "%2e.", true) || kotlin.text.D.l(strB, ".%2e", true) || kotlin.text.D.l(strB, "%2e%2e", true)) {
            if (((String) arrayList.remove(arrayList.size() - 1)).length() != 0 || arrayList.isEmpty()) {
                arrayList.add("");
                return;
            } else {
                arrayList.set(arrayList.size() - 1, "");
                return;
            }
        }
        if (((CharSequence) android.support.v4.media.session.a.e(1, arrayList)).length() == 0) {
            arrayList.set(arrayList.size() - 1, strB);
        } else {
            arrayList.add(strB);
        }
        if (z) {
            arrayList.add("");
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:38:0x00b1  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.String toString() {
        /*
            Method dump skipped, instructions count: 270
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.C1372j.toString():java.lang.String");
    }

    public C1372j() {
        this.a = 1;
        this.f = "";
        this.g = "";
        this.b = -1;
        ArrayList arrayList = new ArrayList();
        this.c = arrayList;
        arrayList.add("");
    }
}
