package retrofit2;

/* loaded from: classes3.dex */
public final class N implements M {
    public static final N b = new N();

    @Override // java.lang.annotation.Annotation
    public final Class annotationType() {
        return M.class;
    }

    @Override // java.lang.annotation.Annotation
    public final boolean equals(Object obj) {
        return obj instanceof M;
    }

    @Override // java.lang.annotation.Annotation
    public final int hashCode() {
        return 0;
    }

    @Override // java.lang.annotation.Annotation
    public final String toString() {
        return assistantMode.refactored.a.i(M.class, new StringBuilder("@"), "()");
    }
}
