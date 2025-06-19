package androidx.work;

import android.app.Application;
import android.content.Context;
import android.content.Intent;
import android.os.Handler;
import android.os.Trace;
import android.view.View;
import androidx.lifecycle.Y;
import com.braze.models.inappmessage.InAppMessageFull;
import com.braze.ui.inappmessage.factories.DefaultInAppMessageFullViewFactory;
import com.braze.ui.inappmessage.views.InAppMessageFullView;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3340g;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3359k2;
import com.google.firebase.perf.network.FirebasePerfUrlConnection;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.OTCallback;
import com.onetrust.otpublishers.headless.Public.Response.OTResponse;
import com.perimeterx.mobile_sdk.block.PXBlockActivity;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final /* synthetic */ class I implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ Object f;

    public /* synthetic */ I(Object obj, Object obj2, Object obj3, Object obj4, Object obj5, int i) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
        this.d = obj3;
        this.e = obj4;
        this.f = obj5;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v13, types: [kotlin.Unit] */
    /* JADX WARN: Type inference failed for: r0v7, types: [kotlin.Unit] */
    @Override // java.lang.Runnable
    public final void run() {
        com.perimeterx.mobile_sdk.doctor_app.model.b bVar;
        Object obj = this.f;
        Object obj2 = this.e;
        Object obj3 = this.c;
        Object obj4 = this.d;
        Object obj5 = this.b;
        switch (this.a) {
            case 0:
                String label = (String) obj3;
                Function0 function0 = (Function0) obj4;
                Y y = (Y) obj2;
                androidx.concurrent.futures.i iVar = (androidx.concurrent.futures.i) obj;
                ((B) obj5).getClass();
                boolean zD = AbstractC3359k2.d();
                if (zD) {
                    try {
                        Intrinsics.checkNotNullParameter(label, "label");
                        Trace.beginSection(AbstractC3359k2.f(label));
                    } finally {
                        if (zD) {
                            Trace.endSection();
                        }
                    }
                }
                try {
                    function0.invoke();
                    F f = G.b;
                    y.j(f);
                    iVar.b(f);
                } catch (Throwable th) {
                    y.j(new E(th));
                    iVar.d(th);
                }
                Unit unit = Unit.a;
                if (zD) {
                    return;
                } else {
                    return;
                }
            case 1:
                DefaultInAppMessageFullViewFactory.createInAppMessageView$lambda$4((View) obj5, (InAppMessageFullView) obj3, (InAppMessageFull) obj4, (Context) obj2, (View) obj);
                return;
            case 2:
                Condition condition = (Condition) obj;
                URL openIdKeyUrl = (URL) obj5;
                Intrinsics.checkNotNullParameter(openIdKeyUrl, "$openIdKeyUrl");
                kotlin.jvm.internal.J result = (kotlin.jvm.internal.J) obj4;
                Intrinsics.checkNotNullParameter(result, "$result");
                String kid = (String) obj3;
                Intrinsics.checkNotNullParameter(kid, "$kid");
                ReentrantLock lock = (ReentrantLock) obj2;
                Intrinsics.checkNotNullParameter(lock, "$lock");
                URLConnection uRLConnection = (URLConnection) FirebasePerfUrlConnection.instrument(openIdKeyUrl.openConnection());
                Intrinsics.e(uRLConnection, "null cannot be cast to non-null type java.net.HttpURLConnection");
                HttpURLConnection httpURLConnection = (HttpURLConnection) uRLConnection;
                try {
                    try {
                        InputStream inputStream = httpURLConnection.getInputStream();
                        Intrinsics.checkNotNullExpressionValue(inputStream, "connection.inputStream");
                        String strB = AbstractC3340g.b(new BufferedReader(new InputStreamReader(inputStream, Charsets.UTF_8), 8192));
                        httpURLConnection.getInputStream().close();
                        result.a = new JSONObject(strB).optString(kid);
                        httpURLConnection.disconnect();
                        lock.lock();
                        try {
                            condition.signal();
                            condition = Unit.a;
                        } finally {
                        }
                    } catch (Throwable th2) {
                        httpURLConnection.disconnect();
                        lock.lock();
                        try {
                            condition.signal();
                            Unit unit2 = Unit.a;
                            throw th2;
                        } finally {
                        }
                    }
                } catch (Exception e) {
                    e.getMessage();
                    httpURLConnection.disconnect();
                    lock.lock();
                    try {
                        condition.signal();
                        condition = Unit.a;
                    } finally {
                    }
                }
                return;
            case 3:
                com.quizlet.data.repository.set.f fVar = (com.quizlet.data.repository.set.f) obj5;
                fVar.getClass();
                OTLogger.c("NetworkRequestHandler", 4, "Parsing IAB data in BG thread.");
                Context context = ((com.onetrust.otpublishers.headless.Internal.Network.d) fVar.d).a;
                new com.onetrust.otpublishers.headless.Internal.Helper.c(context).g(context, (String) ((retrofit2.K) obj3).b);
                OTCallback oTCallback = (OTCallback) obj4;
                if (oTCallback != null) {
                    OTLogger.c("NetworkRequestHandler", 3, "Parsing IAB data complete, sending app callback.");
                    new com.onetrust.otpublishers.headless.Internal.authenticatedconsent.a(context).a();
                    new com.onetrust.otpublishers.headless.Internal.profile.c(context).b();
                    ((Handler) obj2).post(new com.onetrust.otpublishers.headless.Internal.Network.b(oTCallback, (OTResponse) obj, 0));
                    return;
                }
                return;
            default:
                String strF = androidx.compose.ui.node.B.f("toString(...)");
                PXBlockActivity.e.put(strF, (com.perimeterx.mobile_sdk.block.a) obj5);
                Application application = (Application) obj4;
                Intent intent = new Intent(application, (Class<?>) PXBlockActivity.class);
                intent.setFlags(268435456);
                intent.putExtra("uuid", strF);
                intent.putExtra("page", (String) obj3);
                com.perimeterx.mobile_sdk.block.b bVar2 = (com.perimeterx.mobile_sdk.block.b) obj2;
                String str = bVar2.a;
                intent.putExtra("vid", (str == null || str.length() == 0) ? (String) obj : bVar2.a);
                application.startActivity(intent);
                androidx.constraintlayout.core.widgets.analyzer.f fVar2 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                if (fVar2 == null || !fVar2.f() || (bVar = ((com.perimeterx.mobile_sdk.doctor_app.model.d) fVar2.i).e) == null) {
                    return;
                }
                bVar.d = true;
                return;
        }
    }

    public /* synthetic */ I(Object obj, Object obj2, String str, Object obj3, Object obj4, int i) {
        this.a = i;
        this.b = obj;
        this.d = obj2;
        this.c = str;
        this.e = obj3;
        this.f = obj4;
    }
}
