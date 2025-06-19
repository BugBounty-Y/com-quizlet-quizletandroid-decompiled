package com.onetrust.otpublishers.headless.UI.extensions;

import android.graphics.drawable.Drawable;
import com.bumptech.glide.request.e;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;

/* loaded from: classes2.dex */
public final class a implements e {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    public /* synthetic */ a(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    @Override // com.bumptech.glide.request.e
    public final void a(Object obj) throws Exception {
        switch (this.a) {
            case 0:
                OTLogger.c("OneTrust", 3, "Logo shown for " + ((String) this.b) + " for url " + ((String) this.c));
                break;
            default:
                com.quizlet.infra.legacysyncengine.tasks.parse.b bVar = (com.quizlet.infra.legacysyncengine.tasks.parse.b) this.c;
                if (bVar != null) {
                    bVar.accept((Drawable) obj);
                    break;
                }
                break;
        }
    }

    @Override // com.bumptech.glide.request.e
    public final void b() {
        switch (this.a) {
            case 0:
                OTLogger.c("OneTrust", 3, "Logo shown for " + ((String) this.b) + " failed for url " + ((String) this.c));
                break;
            default:
                ((com.quizlet.qutils.rx.b) this.b).run();
                break;
        }
    }
}
