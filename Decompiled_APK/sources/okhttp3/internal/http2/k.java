package okhttp3.internal.http2;

import java.io.IOException;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class k extends okhttp3.internal.concurrent.a {
    public final /* synthetic */ int e = 1;
    public final /* synthetic */ n f;
    public final /* synthetic */ int g;
    public final /* synthetic */ List h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public k(String str, n nVar, int i, List list) {
        super(str, true);
        this.f = nVar;
        this.g = i;
        this.h = list;
    }

    @Override // okhttp3.internal.concurrent.a
    public final long a() {
        switch (this.e) {
            case 0:
                y yVar = this.f.k;
                List responseHeaders = this.h;
                yVar.getClass();
                Intrinsics.checkNotNullParameter(responseHeaders, "responseHeaders");
                try {
                    this.f.w.p(this.g, a.CANCEL);
                    synchronized (this.f) {
                        this.f.y.remove(Integer.valueOf(this.g));
                    }
                    return -1L;
                } catch (IOException unused) {
                    return -1L;
                }
            default:
                y yVar2 = this.f.k;
                List requestHeaders = this.h;
                yVar2.getClass();
                Intrinsics.checkNotNullParameter(requestHeaders, "requestHeaders");
                try {
                    this.f.w.p(this.g, a.CANCEL);
                    synchronized (this.f) {
                        this.f.y.remove(Integer.valueOf(this.g));
                    }
                    return -1L;
                } catch (IOException unused2) {
                    return -1L;
                }
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public k(String str, n nVar, int i, List list, boolean z) {
        super(str, true);
        this.f = nVar;
        this.g = i;
        this.h = list;
    }
}
