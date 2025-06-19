package androidx.camera.camera2.internal;

import android.os.Handler;
import androidx.camera.core.impl.A0;
import androidx.camera.core.impl.C0168g;
import androidx.camera.core.impl.InterfaceC0185y;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.OTCallback;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import java.util.List;
import java.util.Map;

/* renamed from: androidx.camera.camera2.internal.s, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class RunnableC0141s implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ Object f;
    public final /* synthetic */ Object g;

    public /* synthetic */ RunnableC0141s(com.onetrust.otpublishers.headless.Internal.Network.d dVar, retrofit2.K k, String str, OTCallback oTCallback, Handler handler, OTPublishersHeadlessSDK oTPublishersHeadlessSDK) {
        this.a = 2;
        this.b = dVar;
        this.d = k;
        this.c = str;
        this.e = oTCallback;
        this.f = handler;
        this.g = oTPublishersHeadlessSDK;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                C c = (C) this.b;
                String str = (String) this.c;
                androidx.camera.core.impl.q0 q0Var = (androidx.camera.core.impl.q0) this.d;
                A0 a0 = (A0) this.e;
                C0168g c0168g = (C0168g) this.f;
                List list = (List) this.g;
                c.getClass();
                c.t("Use case " + str + " RESET");
                c.a.i(str, q0Var, a0, c0168g, list);
                c.p();
                c.D();
                c.K();
                if (c.H == 9) {
                    c.B();
                    break;
                }
                break;
            case 1:
                ((com.quizlet.data.repository.folderwithcreatorinclass.e) this.b).d((InterfaceC0185y) this.c, (InterfaceC0185y) this.d, (androidx.camera.core.processing.k) this.e, (androidx.camera.core.processing.k) this.f, (Map.Entry) this.g);
                break;
            default:
                com.onetrust.otpublishers.headless.Internal.Network.d dVar = (com.onetrust.otpublishers.headless.Internal.Network.d) this.b;
                dVar.getClass();
                OTLogger.c("NetworkRequestHandler", 4, "parsing appdata in BG thread");
                dVar.g((retrofit2.K) this.d, (String) this.c, (OTCallback) this.e, (Handler) this.f, (OTPublishersHeadlessSDK) this.g, true);
                break;
        }
    }

    public /* synthetic */ RunnableC0141s(Object obj, Object obj2, Object obj3, Object obj4, Object obj5, Object obj6, int i) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
        this.d = obj3;
        this.e = obj4;
        this.f = obj5;
        this.g = obj6;
    }
}
