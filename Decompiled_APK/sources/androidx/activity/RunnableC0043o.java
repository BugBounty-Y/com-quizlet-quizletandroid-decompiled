package androidx.activity;

import android.content.Intent;
import android.content.IntentSender;
import android.hardware.camera2.CameraCaptureSession;
import android.hardware.camera2.CameraDevice;
import android.view.View;
import androidx.camera.camera2.internal.C0135l;
import androidx.camera.camera2.internal.C0144v;
import androidx.camera.core.impl.AbstractC0171j;
import androidx.camera.core.impl.InterfaceC0177p;
import androidx.recyclerview.widget.AbstractC1381n0;
import androidx.recyclerview.widget.RecyclerView;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.quizlet.quizletandroid.ui.preview.SetPreviewActivity;
import java.io.Serializable;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;

/* renamed from: androidx.activity.o, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class RunnableC0043o implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ int c;
    public final /* synthetic */ Object d;

    public /* synthetic */ RunnableC0043o(Object obj, int i, Object obj2, int i2) {
        this.a = i2;
        this.b = obj;
        this.c = i;
        this.d = obj2;
    }

    @Override // java.lang.Runnable
    public final void run() throws JSONException {
        Object obj = this.d;
        int i = this.c;
        Object obj2 = this.b;
        switch (this.a) {
            case 0:
                Serializable serializable = (Serializable) ((androidx.webkit.internal.p) obj).b;
                C0044p c0044p = (C0044p) obj2;
                String str = (String) c0044p.a.get(Integer.valueOf(i));
                if (str != null) {
                    androidx.activity.result.d dVar = (androidx.activity.result.d) c0044p.e.get(str);
                    if ((dVar != null ? dVar.a : null) != null) {
                        androidx.activity.result.a aVar = dVar.a;
                        Intrinsics.e(aVar, "null cannot be cast to non-null type androidx.activity.result.ActivityResultCallback<O of androidx.activity.result.ActivityResultRegistry.dispatchResult>");
                        if (c0044p.d.remove(str)) {
                            aVar.a(serializable);
                            break;
                        }
                    } else {
                        c0044p.g.remove(str);
                        c0044p.f.put(str, serializable);
                        break;
                    }
                }
                break;
            case 1:
                ((C0044p) obj2).a(i, 0, new Intent().setAction("androidx.activity.result.contract.action.INTENT_SENDER_REQUEST").putExtra("androidx.activity.result.contract.extra.SEND_INTENT_EXCEPTION", (IntentSender.SendIntentException) obj));
                break;
            case 2:
                ((AbstractC0171j) obj2).c(i, (assistantMode.utils.studiableMetadata.b) obj);
                break;
            case 3:
                ((AbstractC0171j) obj2).b(i, (InterfaceC0177p) obj);
                break;
            case 4:
                ((CameraCaptureSession.CaptureCallback) ((C0135l) obj2).b).onCaptureSequenceAborted((CameraCaptureSession) obj, i);
                break;
            case 5:
                ((CameraDevice.StateCallback) ((C0144v) obj2).b).onError((CameraDevice) obj, i);
                break;
            case 6:
                ((androidx.profileinstaller.c) ((androidx.profileinstaller.a) obj2).e).b(i, (Serializable) obj);
                break;
            case 7:
                com.onetrust.otpublishers.headless.UI.TVUI.fragments.g gVar = (com.onetrust.otpublishers.headless.UI.TVUI.fragments.g) obj2;
                gVar.getClass();
                OTLogger.c("OneTrust", 4, "Saving Consent on BG thread");
                String str2 = (String) obj;
                gVar.u.saveConsent(str2);
                assistantMode.utils.studiableMetadata.b bVar = gVar.x;
                androidx.compose.foundation.lazy.grid.m mVar = new androidx.compose.foundation.lazy.grid.m(i, 4);
                com.onetrust.otpublishers.headless.Internal.Event.a aVar2 = gVar.v;
                bVar.getClass();
                assistantMode.utils.studiableMetadata.b.y(mVar, aVar2);
                androidx.compose.foundation.lazy.grid.m mVar2 = new androidx.compose.foundation.lazy.grid.m(17, 4);
                mVar2.d = str2;
                assistantMode.utils.studiableMetadata.b bVar2 = gVar.x;
                com.onetrust.otpublishers.headless.Internal.Event.a aVar3 = gVar.v;
                bVar2.getClass();
                assistantMode.utils.studiableMetadata.b.y(mVar2, aVar3);
                break;
            default:
                String str3 = SetPreviewActivity.u;
                RecyclerView recyclerView = (RecyclerView) obj2;
                AbstractC1381n0 layoutManager = recyclerView.getLayoutManager();
                View viewQ = layoutManager != null ? layoutManager.q(i) : null;
                if (viewQ != null) {
                    int[] iArrB = ((SetPreviewActivity) obj).t.b(layoutManager, viewQ);
                    int i2 = iArrB[0];
                    if (i2 != 0 || iArrB[1] != 0) {
                        recyclerView.scrollBy(i2, iArrB[1]);
                        break;
                    }
                }
                break;
        }
    }

    public /* synthetic */ RunnableC0043o(Object obj, Object obj2, int i, int i2) {
        this.a = i2;
        this.b = obj;
        this.d = obj2;
        this.c = i;
    }
}
