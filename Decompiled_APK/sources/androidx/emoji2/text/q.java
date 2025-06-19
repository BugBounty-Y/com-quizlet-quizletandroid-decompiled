package androidx.emoji2.text;

/* loaded from: classes.dex */
public final class q implements p {
    public final int a;
    public int b = -1;
    public int c = -1;

    public q(int i) {
        this.a = i;
    }

    @Override // androidx.emoji2.text.p
    public final Object a() {
        return this;
    }

    @Override // androidx.emoji2.text.p
    public final boolean d(CharSequence charSequence, int i, int i2, y yVar) {
        int i3 = this.a;
        if (i > i3 || i3 >= i2) {
            return i2 <= i3;
        }
        this.b = i;
        this.c = i2;
        return false;
    }
}
