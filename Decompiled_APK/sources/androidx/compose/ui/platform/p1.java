package androidx.compose.ui.platform;

import android.content.ContentResolver;
import android.content.Context;
import android.net.Uri;
import android.os.Looper;
import android.provider.Settings;
import android.view.View;
import androidx.compose.runtime.AbstractC0827t;
import androidx.datastore.core.C1087t;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3224o6;
import com.google.android.gms.internal.mlkit_vision_camera.D1;
import com.quizlet.quizletandroid.R;
import java.util.LinkedHashMap;

/* loaded from: classes.dex */
public abstract class p1 {
    public static final LinkedHashMap a = new LinkedHashMap();

    public static final kotlinx.coroutines.flow.q0 a(Context context) {
        kotlinx.coroutines.flow.q0 q0Var;
        LinkedHashMap linkedHashMap = a;
        synchronized (linkedHashMap) {
            try {
                Object objX = linkedHashMap.get(context);
                if (objX == null) {
                    ContentResolver contentResolver = context.getContentResolver();
                    Uri uriFor = Settings.Global.getUriFor("animator_duration_scale");
                    kotlinx.coroutines.channels.h hVarA = D1.a(-1, 6, null);
                    C1087t c1087t = new C1087t(new n1(contentResolver, uriFor, new o1(hVarA, AbstractC3224o6.b(Looper.getMainLooper())), hVarA, context, null));
                    kotlinx.coroutines.A0 a0E = kotlinx.coroutines.E.e();
                    kotlinx.coroutines.scheduling.e eVar = kotlinx.coroutines.O.a;
                    objX = kotlinx.coroutines.flow.e0.x(c1087t, new kotlinx.coroutines.internal.d(kotlin.coroutines.k.c(kotlinx.coroutines.internal.m.a, a0E)), kotlinx.coroutines.flow.h0.a(3), Float.valueOf(Settings.Global.getFloat(context.getContentResolver(), "animator_duration_scale", 1.0f)));
                    linkedHashMap.put(context, objX);
                }
                q0Var = (kotlinx.coroutines.flow.q0) objX;
            } catch (Throwable th) {
                throw th;
            }
        }
        return q0Var;
    }

    public static final AbstractC0827t b(View view) {
        Object tag = view.getTag(R.id.androidx_compose_ui_view_composition_context);
        if (tag instanceof AbstractC0827t) {
            return (AbstractC0827t) tag;
        }
        return null;
    }
}
