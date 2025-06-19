package com.google.android.gms.internal.play_billing;

/* renamed from: com.google.android.gms.internal.play_billing.u, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3838u extends AbstractC3841v {
    public static final C3838u b = new C3838u(0);
    public static final C3838u c = new C3838u(1);
    public final /* synthetic */ int a;

    public /* synthetic */ C3838u(int i) {
        this.a = i;
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3841v
    public final int a(AbstractC3841v abstractC3841v) {
        switch (this.a) {
            case 0:
                return abstractC3841v == this ? 0 : 1;
            default:
                return abstractC3841v == this ? 0 : -1;
        }
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3841v
    public final void b(StringBuilder sb) {
        switch (this.a) {
            case 0:
                throw new AssertionError();
            default:
                sb.append("(-∞");
                return;
        }
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3841v
    public final void c(StringBuilder sb) {
        switch (this.a) {
            case 0:
                sb.append("+∞)");
                return;
            default:
                throw new AssertionError();
        }
    }

    @Override // java.lang.Comparable
    public final int compareTo(Object obj) {
        switch (this.a) {
            case 0:
                return ((AbstractC3841v) obj) == this ? 0 : 1;
            default:
                return ((AbstractC3841v) obj) == this ? 0 : -1;
        }
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3841v
    public final int hashCode() {
        switch (this.a) {
        }
        return System.identityHashCode(this);
    }

    public final String toString() {
        switch (this.a) {
            case 0:
                return "+∞";
            default:
                return "-∞";
        }
    }
}
