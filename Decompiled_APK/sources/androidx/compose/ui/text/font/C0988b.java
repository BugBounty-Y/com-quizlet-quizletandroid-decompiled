package androidx.compose.ui.text.font;

/* renamed from: androidx.compose.ui.text.font.b, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0988b implements y {
    public final int a;

    public C0988b(int i) {
        this.a = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C0988b) && this.a == ((C0988b) obj).a;
    }

    public final int hashCode() {
        return Integer.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.q(new StringBuilder("AndroidFontResolveInterceptor(fontWeightAdjustment="), this.a, ')');
    }
}
