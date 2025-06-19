package coil3.decode;

import java.io.IOException;
import okio.C5091h;
import okio.G;
import okio.InterfaceC5093j;
import retrofit2.C5193s;

/* loaded from: classes.dex */
public final class b extends okio.o {
    public final /* synthetic */ int b = 0;
    public Object c;

    public /* synthetic */ b(G g) {
        super(g);
    }

    @Override // okio.o, okio.G
    public final long b0(C5091h c5091h, long j) throws Exception {
        switch (this.b) {
            case 0:
                try {
                    return super.b0(c5091h, j);
                } catch (Exception e) {
                    this.c = e;
                    throw e;
                }
            default:
                try {
                    return super.b0(c5091h, j);
                } catch (IOException e2) {
                    ((C5193s) this.c).c = e2;
                    throw e2;
                }
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(C5193s c5193s, InterfaceC5093j interfaceC5093j) {
        super(interfaceC5093j);
        this.c = c5193s;
    }
}
