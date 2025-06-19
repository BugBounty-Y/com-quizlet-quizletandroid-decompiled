package androidx.compose.ui.text;

import java.util.ArrayList;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.ui.text.g, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0995g implements CharSequence {
    public final String a;
    public final List b;
    public final List c;
    public final List d;

    static {
        com.quizlet.data.repository.explanations.myexplanations.a aVar = C.a;
    }

    public C0995g(String str, List list, List list2, List list3) {
        List listN0;
        this.a = str;
        this.b = list;
        this.c = list2;
        this.d = list3;
        if (list2 == null || (listN0 = CollectionsKt.n0(list2, new C0986f())) == null) {
            return;
        }
        int size = listN0.size();
        int i = -1;
        int i2 = 0;
        while (i2 < size) {
            C0985e c0985e = (C0985e) listN0.get(i2);
            if (c0985e.b < i) {
                throw new IllegalArgumentException("ParagraphStyle should not overlap");
            }
            int length = this.a.length();
            int i3 = c0985e.c;
            if (i3 > length) {
                throw new IllegalArgumentException(("ParagraphStyle range [" + c0985e.b + ", " + i3 + ") is out of boundary").toString());
            }
            i2++;
            i = i3;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v0, types: [kotlin.collections.K] */
    /* JADX WARN: Type inference failed for: r1v1, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r1v2, types: [java.util.ArrayList] */
    public final List a(int i) {
        ?? arrayList;
        List list = this.d;
        if (list != null) {
            arrayList = new ArrayList(list.size());
            int size = list.size();
            for (int i2 = 0; i2 < size; i2++) {
                Object obj = list.get(i2);
                C0985e c0985e = (C0985e) obj;
                if ((c0985e.a instanceof AbstractC1013n) && AbstractC0996h.c(0, i, c0985e.b, c0985e.c)) {
                    arrayList.add(obj);
                }
            }
        } else {
            arrayList = kotlin.collections.K.a;
        }
        Intrinsics.e(arrayList, "null cannot be cast to non-null type kotlin.collections.List<androidx.compose.ui.text.AnnotatedString.Range<androidx.compose.ui.text.LinkAnnotation>>");
        return arrayList;
    }

    public final List b() {
        List list = this.b;
        return list == null ? kotlin.collections.K.a : list;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v0, types: [kotlin.collections.K] */
    /* JADX WARN: Type inference failed for: r1v1, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r1v2, types: [java.util.ArrayList] */
    public final List c(int i, int i2, String str) {
        ?? arrayList;
        List list = this.d;
        if (list != null) {
            arrayList = new ArrayList(list.size());
            int size = list.size();
            for (int i3 = 0; i3 < size; i3++) {
                Object obj = list.get(i3);
                C0985e c0985e = (C0985e) obj;
                if ((c0985e.a instanceof String) && str.equals(c0985e.d) && AbstractC0996h.c(i, i2, c0985e.b, c0985e.c)) {
                    arrayList.add(obj);
                }
            }
        } else {
            arrayList = kotlin.collections.K.a;
        }
        Intrinsics.e(arrayList, "null cannot be cast to non-null type kotlin.collections.List<androidx.compose.ui.text.AnnotatedString.Range<kotlin.String>>");
        return arrayList;
    }

    @Override // java.lang.CharSequence
    public final char charAt(int i) {
        return this.a.charAt(i);
    }

    @Override // java.lang.CharSequence
    /* renamed from: d, reason: merged with bridge method [inline-methods] */
    public final C0995g subSequence(int i, int i2) {
        if (i > i2) {
            throw new IllegalArgumentException(("start (" + i + ") should be less or equal to end (" + i2 + ')').toString());
        }
        String str = this.a;
        if (i == 0 && i2 == str.length()) {
            return this;
        }
        String strSubstring = str.substring(i, i2);
        Intrinsics.checkNotNullExpressionValue(strSubstring, "this as java.lang.String…ing(startIndex, endIndex)");
        return new C0995g(strSubstring, AbstractC0996h.a(i, i2, this.b), AbstractC0996h.a(i, i2, this.c), AbstractC0996h.a(i, i2, this.d));
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C0995g)) {
            return false;
        }
        C0995g c0995g = (C0995g) obj;
        return Intrinsics.b(this.a, c0995g.a) && Intrinsics.b(this.b, c0995g.b) && Intrinsics.b(this.c, c0995g.c) && Intrinsics.b(this.d, c0995g.d);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        List list = this.b;
        int iHashCode2 = (iHashCode + (list != null ? list.hashCode() : 0)) * 31;
        List list2 = this.c;
        int iHashCode3 = (iHashCode2 + (list2 != null ? list2.hashCode() : 0)) * 31;
        List list3 = this.d;
        return iHashCode3 + (list3 != null ? list3.hashCode() : 0);
    }

    @Override // java.lang.CharSequence
    public final int length() {
        return this.a.length();
    }

    @Override // java.lang.CharSequence
    public final String toString() {
        return this.a;
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public C0995g(int i, String str, ArrayList arrayList) {
        List list = (i & 2) != 0 ? kotlin.collections.K.a : arrayList;
        kotlin.collections.K k = kotlin.collections.K.a;
        List list2 = list.isEmpty() ? null : list;
        k.getClass();
        this(str, list2, null, null);
    }
}
