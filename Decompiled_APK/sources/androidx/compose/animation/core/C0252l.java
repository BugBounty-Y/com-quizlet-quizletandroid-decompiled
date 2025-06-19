package androidx.compose.animation.core;

/* renamed from: androidx.compose.animation.core.l, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0252l {
    public final C0258o a;
    public final int b;

    public C0252l(int i, C0258o c0258o) {
        this.a = c0258o;
        this.b = i;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("AnimationResult(endReason=");
        int i = this.b;
        sb.append(i != 1 ? i != 2 ? "null" : "Finished" : "BoundReached");
        sb.append(", endState=");
        sb.append(this.a);
        sb.append(')');
        return sb.toString();
    }
}
