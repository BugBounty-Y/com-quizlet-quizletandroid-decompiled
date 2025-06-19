package androidx.browser.customtabs;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import com.google.android.gms.internal.ads.AbstractC2025es;
import com.google.android.gms.internal.ads.G7;
import java.lang.ref.WeakReference;

/* loaded from: classes.dex */
public final class b extends m {
    public final /* synthetic */ int b = 0;
    public final Object c;

    public b(Context context) {
        this.c = context;
    }

    private final void b(ComponentName componentName) {
    }

    @Override // androidx.browser.customtabs.m
    public final void a(ComponentName componentName, l lVar) {
        switch (this.b) {
            case 0:
                lVar.d();
                ((Context) this.c).unbindService(this);
                break;
            default:
                G7 g7 = (G7) ((WeakReference) this.c).get();
                if (g7 != null) {
                    g7.b = lVar;
                    lVar.d();
                    io.ktor.client.plugins.api.d dVar = g7.d;
                    if (dVar != null) {
                        G7 g72 = (G7) dVar.b;
                        l lVar2 = g72.b;
                        if (lVar2 == null) {
                            g72.a = null;
                        } else if (g72.a == null) {
                            g72.a = lVar2.c(null);
                        }
                        androidx.work.impl.model.c cVarC = new k(g72.a).c();
                        Context context = (Context) dVar.c;
                        ((Intent) cVarC.b).setPackage(AbstractC2025es.i(context));
                        cVarC.v(context, (Uri) dVar.d);
                        Activity activity = (Activity) context;
                        b bVar = g72.c;
                        if (bVar != null) {
                            activity.unbindService(bVar);
                            g72.b = null;
                            g72.a = null;
                            g72.c = null;
                            break;
                        }
                    }
                }
                break;
        }
    }

    @Override // android.content.ServiceConnection
    public final void onServiceDisconnected(ComponentName componentName) {
        switch (this.b) {
            case 0:
                break;
            default:
                G7 g7 = (G7) ((WeakReference) this.c).get();
                if (g7 != null) {
                    g7.b = null;
                    g7.a = null;
                    break;
                }
                break;
        }
    }

    public b(G7 g7) {
        this.c = new WeakReference(g7);
    }
}
