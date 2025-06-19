package retrofit2;

import java.util.Objects;

/* loaded from: classes3.dex */
public final class x extends S {
    public final /* synthetic */ int d;
    public final String e;
    public final C5176a f;
    public final boolean g;

    public x(String str, int i, boolean z) {
        this.d = i;
        switch (i) {
            case 1:
                C5176a c5176a = C5176a.b;
                Objects.requireNonNull(str, "name == null");
                this.e = str;
                this.f = c5176a;
                this.g = z;
                break;
            case 2:
                C5176a c5176a2 = C5176a.b;
                Objects.requireNonNull(str, "name == null");
                this.e = str;
                this.f = c5176a2;
                this.g = z;
                break;
            default:
                C5176a c5176a3 = C5176a.b;
                Objects.requireNonNull(str, "name == null");
                this.e = str;
                this.f = c5176a3;
                this.g = z;
                break;
        }
    }

    @Override // retrofit2.S
    public final void a(H h, Object obj) {
        switch (this.d) {
            case 0:
                if (obj != null) {
                    this.f.getClass();
                    String string = obj.toString();
                    if (string != null) {
                        h.a(this.e, string, this.g);
                        break;
                    }
                }
                break;
            case 1:
                if (obj != null) {
                    this.f.getClass();
                    String string2 = obj.toString();
                    if (string2 != null) {
                        h.b(this.e, string2, this.g);
                        break;
                    }
                }
                break;
            default:
                if (obj != null) {
                    this.f.getClass();
                    String string3 = obj.toString();
                    if (string3 != null) {
                        h.d(this.e, string3, this.g);
                        break;
                    }
                }
                break;
        }
    }
}
