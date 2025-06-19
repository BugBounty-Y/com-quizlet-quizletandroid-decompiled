package androidx.compose.ui.text;

import java.util.ArrayList;
import java.util.List;

/* renamed from: androidx.compose.ui.text.d, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0984d implements Appendable {
    public final StringBuilder a;
    public final ArrayList b;
    public final ArrayList c;
    public final ArrayList d;
    public final ArrayList e;

    public C0984d() {
        this.a = new StringBuilder(16);
        this.b = new ArrayList();
        this.c = new ArrayList();
        this.d = new ArrayList();
        this.e = new ArrayList();
    }

    public final void a(C1011l c1011l, int i, int i2) {
        this.d.add(new C0983c(c1011l, i, i2, 8));
    }

    @Override // java.lang.Appendable
    public final /* bridge */ /* synthetic */ Appendable append(CharSequence charSequence) {
        e(charSequence);
        return this;
    }

    public final void b(String str, int i, String str2, int i2) {
        this.d.add(new C0983c(i, i2, str2, str));
    }

    public final void c(D d, int i, int i2) {
        this.b.add(new C0983c(d, i, i2, 8));
    }

    public final void d(C0995g c0995g) {
        StringBuilder sb = this.a;
        int length = sb.length();
        sb.append(c0995g.a);
        List list = c0995g.b;
        if (list != null) {
            int size = list.size();
            for (int i = 0; i < size; i++) {
                C0985e c0985e = (C0985e) list.get(i);
                c((D) c0985e.a, c0985e.b + length, c0985e.c + length);
            }
        }
        List list2 = c0995g.c;
        if (list2 != null) {
            int size2 = list2.size();
            for (int i2 = 0; i2 < size2; i2++) {
                C0985e c0985e2 = (C0985e) list2.get(i2);
                this.c.add(new C0983c((t) c0985e2.a, c0985e2.b + length, c0985e2.c + length, 8));
            }
        }
        List list3 = c0995g.d;
        if (list3 != null) {
            int size3 = list3.size();
            for (int i3 = 0; i3 < size3; i3++) {
                C0985e c0985e3 = (C0985e) list3.get(i3);
                this.d.add(new C0983c(c0985e3.b + length, c0985e3.c + length, c0985e3.a, c0985e3.d));
            }
        }
    }

    public final void e(CharSequence charSequence) {
        if (charSequence instanceof C0995g) {
            d((C0995g) charSequence);
        } else {
            this.a.append(charSequence);
        }
    }

    public final void f(String str) {
        this.a.append(str);
    }

    public final void g() {
        ArrayList arrayList = this.e;
        if (arrayList.isEmpty()) {
            throw new IllegalStateException("Nothing to pop.");
        }
        ((C0983c) arrayList.remove(arrayList.size() - 1)).c = this.a.length();
    }

    public final void h(int i) {
        ArrayList arrayList = this.e;
        if (i < arrayList.size()) {
            while (arrayList.size() - 1 >= i) {
                g();
            }
        } else {
            throw new IllegalStateException((i + " should be less than " + arrayList.size()).toString());
        }
    }

    public final int i(D d) {
        C0983c c0983c = new C0983c(d, this.a.length(), 0, 12);
        this.e.add(c0983c);
        this.b.add(c0983c);
        return r5.size() - 1;
    }

    public final C0995g j() {
        StringBuilder sb = this.a;
        String string = sb.toString();
        ArrayList arrayList = this.b;
        ArrayList arrayList2 = new ArrayList(arrayList.size());
        int size = arrayList.size();
        for (int i = 0; i < size; i++) {
            arrayList2.add(((C0983c) arrayList.get(i)).a(sb.length()));
        }
        if (arrayList2.isEmpty()) {
            arrayList2 = null;
        }
        ArrayList arrayList3 = this.c;
        ArrayList arrayList4 = new ArrayList(arrayList3.size());
        int size2 = arrayList3.size();
        for (int i2 = 0; i2 < size2; i2++) {
            arrayList4.add(((C0983c) arrayList3.get(i2)).a(sb.length()));
        }
        if (arrayList4.isEmpty()) {
            arrayList4 = null;
        }
        ArrayList arrayList5 = this.d;
        ArrayList arrayList6 = new ArrayList(arrayList5.size());
        int size3 = arrayList5.size();
        for (int i3 = 0; i3 < size3; i3++) {
            arrayList6.add(((C0983c) arrayList5.get(i3)).a(sb.length()));
        }
        return new C0995g(string, arrayList2, arrayList4, arrayList6.isEmpty() ? null : arrayList6);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v3, types: [java.util.List] */
    /* JADX WARN: Type inference failed for: r1v4, types: [java.util.ArrayList] */
    /* JADX WARN: Type inference failed for: r1v5 */
    /* JADX WARN: Type inference failed for: r8v0 */
    /* JADX WARN: Type inference failed for: r8v1, types: [java.util.List] */
    /* JADX WARN: Type inference failed for: r8v10, types: [java.util.ArrayList] */
    /* JADX WARN: Type inference failed for: r8v9, types: [java.util.List] */
    @Override // java.lang.Appendable
    public final Appendable append(CharSequence charSequence, int i, int i2) {
        ?? arrayList;
        List list;
        ?? arrayList2;
        boolean z = charSequence instanceof C0995g;
        StringBuilder sb = this.a;
        if (!z) {
            sb.append(charSequence, i, i2);
            return this;
        }
        C0995g c0995g = (C0995g) charSequence;
        int length = sb.length();
        sb.append((CharSequence) c0995g.a, i, i2);
        List listB = AbstractC0996h.b(c0995g, i, i2);
        if (listB != null) {
            int size = listB.size();
            for (int i3 = 0; i3 < size; i3++) {
                C0985e c0985e = (C0985e) listB.get(i3);
                c((D) c0985e.a, c0985e.b + length, c0985e.c + length);
            }
        }
        String str = c0995g.a;
        if (i == i2 || (arrayList = c0995g.c) == 0) {
            arrayList = 0;
        } else if (i != 0 || i2 < str.length()) {
            ArrayList arrayList3 = new ArrayList(arrayList.size());
            int size2 = arrayList.size();
            for (int i4 = 0; i4 < size2; i4++) {
                Object obj = arrayList.get(i4);
                C0985e c0985e2 = (C0985e) obj;
                if (AbstractC0996h.c(i, i2, c0985e2.b, c0985e2.c)) {
                    arrayList3.add(obj);
                }
            }
            arrayList = new ArrayList(arrayList3.size());
            int size3 = arrayList3.size();
            for (int i5 = 0; i5 < size3; i5++) {
                C0985e c0985e3 = (C0985e) arrayList3.get(i5);
                arrayList.add(new C0985e(c0985e3.a, kotlin.ranges.l.c(c0985e3.b, i, i2) - i, kotlin.ranges.l.c(c0985e3.c, i, i2) - i));
            }
        }
        if (arrayList != 0) {
            int size4 = arrayList.size();
            for (int i6 = 0; i6 < size4; i6++) {
                C0985e c0985e4 = (C0985e) arrayList.get(i6);
                this.c.add(new C0983c((t) c0985e4.a, c0985e4.b + length, c0985e4.c + length, 8));
            }
        }
        if (i == i2 || (arrayList2 = c0995g.d) == 0) {
            list = null;
        } else {
            if (i != 0 || i2 < str.length()) {
                ArrayList arrayList4 = new ArrayList(arrayList2.size());
                int size5 = arrayList2.size();
                for (int i7 = 0; i7 < size5; i7++) {
                    Object obj2 = arrayList2.get(i7);
                    C0985e c0985e5 = (C0985e) obj2;
                    if (AbstractC0996h.c(i, i2, c0985e5.b, c0985e5.c)) {
                        arrayList4.add(obj2);
                    }
                }
                arrayList2 = new ArrayList(arrayList4.size());
                int size6 = arrayList4.size();
                for (int i8 = 0; i8 < size6; i8++) {
                    C0985e c0985e6 = (C0985e) arrayList4.get(i8);
                    arrayList2.add(new C0985e(kotlin.ranges.l.c(c0985e6.b, i, i2) - i, kotlin.ranges.l.c(c0985e6.c, i, i2) - i, c0985e6.a, c0985e6.d));
                }
            }
            list = arrayList2;
        }
        if (list != null) {
            int size7 = list.size();
            for (int i9 = 0; i9 < size7; i9++) {
                C0985e c0985e7 = (C0985e) list.get(i9);
                this.d.add(new C0983c(c0985e7.b + length, c0985e7.c + length, c0985e7.a, c0985e7.d));
            }
        }
        return this;
    }

    public C0984d(C0995g c0995g) {
        this();
        d(c0995g);
    }

    @Override // java.lang.Appendable
    public final Appendable append(char c) {
        this.a.append(c);
        return this;
    }
}
