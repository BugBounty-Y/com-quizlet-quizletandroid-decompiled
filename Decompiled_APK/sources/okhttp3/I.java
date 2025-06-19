package okhttp3;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3347h2;
import java.util.regex.Pattern;
import kotlin.jvm.internal.Intrinsics;
import okio.C5091h;
import okio.InterfaceC5093j;

/* loaded from: classes3.dex */
public final class I extends J {
    public final /* synthetic */ int a = 1;
    public final long b;
    public final Object c;
    public final InterfaceC5093j d;

    public I(String str, long j, okio.A source) {
        Intrinsics.checkNotNullParameter(source, "source");
        this.c = str;
        this.b = j;
        this.d = source;
    }

    @Override // okhttp3.J
    public final long a() {
        switch (this.a) {
        }
        return this.b;
    }

    @Override // okhttp3.J
    public final w d() {
        Object obj = this.c;
        switch (this.a) {
            case 0:
                return (w) obj;
            default:
                String str = (String) obj;
                if (str == null) {
                    return null;
                }
                Pattern pattern = w.e;
                return AbstractC3347h2.d(str);
        }
    }

    @Override // okhttp3.J
    public final InterfaceC5093j f0() {
        switch (this.a) {
            case 0:
                return (C5091h) this.d;
            default:
                return (okio.A) this.d;
        }
    }

    public I(w wVar, long j, C5091h c5091h) {
        this.c = wVar;
        this.b = j;
        this.d = c5091h;
    }
}
