package androidx.constraintlayout.core.parser;

/* loaded from: classes.dex */
public final class h extends c {
    public static h i(String str) {
        h hVar = new h(str.toCharArray());
        hVar.b = 0L;
        long length = str.length() - 1;
        if (hVar.c == Long.MAX_VALUE) {
            hVar.c = length;
            b bVar = hVar.d;
            if (bVar != null) {
                bVar.i(hVar);
            }
        }
        return hVar;
    }

    @Override // androidx.constraintlayout.core.parser.c
    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if ((obj instanceof h) && c().equals(((h) obj).c())) {
            return true;
        }
        return super.equals(obj);
    }
}
