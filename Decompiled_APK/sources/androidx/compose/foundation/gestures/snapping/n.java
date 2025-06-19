package androidx.compose.foundation.gestures.snapping;

/* loaded from: classes.dex */
public final class n implements o {
    public static final n b = new n(0);
    public static final n c = new n(1);
    public final /* synthetic */ int a;

    public /* synthetic */ n(int i) {
        this.a = i;
    }

    @Override // androidx.compose.foundation.gestures.snapping.o
    public final int b(int i, int i2, int i3, int i4) {
        switch (this.a) {
            case 0:
                return (((i - i3) - i4) / 2) - (i2 / 2);
            default:
                return 0;
        }
    }

    public final String toString() {
        switch (this.a) {
            case 0:
                return "Center";
            default:
                return "Start";
        }
    }
}
