package androidx.navigation;

import android.app.Activity;
import android.content.Context;
import android.content.ContextWrapper;
import androidx.compose.animation.core.AbstractC0240f;
import androidx.lifecycle.p0;
import androidx.navigation.compose.C1268a;
import com.comscore.streaming.EventType;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.io.File;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.navigation.a, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class C1265a implements Function1 {
    public final /* synthetic */ int a;

    public /* synthetic */ C1265a(int i) {
        this.a = i;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        int i = 1;
        int i2 = 0;
        int i3 = 2;
        switch (this.a) {
            case 0:
                Context it2 = (Context) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                if (it2 instanceof ContextWrapper) {
                    return ((ContextWrapper) it2).getBaseContext();
                }
                return null;
            case 1:
                Context it3 = (Context) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                if (it3 instanceof ContextWrapper) {
                    return ((ContextWrapper) it3).getBaseContext();
                }
                return null;
            case 2:
                C1282d anim = (C1282d) obj;
                Intrinsics.checkNotNullParameter(anim, "$this$anim");
                anim.a = 0;
                anim.b = 0;
                return Unit.a;
            case 3:
                Y popUpTo = (Y) obj;
                Intrinsics.checkNotNullParameter(popUpTo, "$this$popUpTo");
                popUpTo.b = true;
                return Unit.a;
            case 4:
                Intrinsics.checkNotNullParameter((androidx.lifecycle.viewmodel.c) obj, "$this$initializer");
                return new C1296s();
            case 5:
                Context it4 = (Context) obj;
                Intrinsics.checkNotNullParameter(it4, "it");
                ContextWrapper contextWrapper = it4 instanceof ContextWrapper ? (ContextWrapper) it4 : null;
                if (contextWrapper != null) {
                    return contextWrapper.getBaseContext();
                }
                return null;
            case 6:
                Context it5 = (Context) obj;
                Intrinsics.checkNotNullParameter(it5, "it");
                if (it5 instanceof Activity) {
                    return (Activity) it5;
                }
                return null;
            case 7:
                B it6 = (B) obj;
                Intrinsics.checkNotNullParameter(it6, "it");
                return it6.c;
            case 8:
                B it7 = (B) obj;
                Intrinsics.checkNotNullParameter(it7, "it");
                if (!(it7 instanceof D)) {
                    return null;
                }
                androidx.camera.camera2.internal.concurrent.a aVar = ((D) it7).f;
                return aVar.s(aVar.b);
            case 9:
                Intrinsics.checkNotNullParameter((Y) obj, "<this>");
                return Unit.a;
            case 10:
                L navOptions = (L) obj;
                Intrinsics.checkNotNullParameter(navOptions, "$this$navOptions");
                navOptions.b = true;
                return Unit.a;
            case 11:
                return new C1268a(p0.c((androidx.lifecycle.viewmodel.c) obj));
            case 12:
                return androidx.compose.animation.V.c(AbstractC0240f.r(700, 0, null, 6), 2);
            case 13:
                return androidx.compose.animation.V.c(AbstractC0240f.r(700, 0, null, 6), 2);
            case 14:
                return androidx.compose.animation.V.d(AbstractC0240f.r(700, 0, null, 6), 2);
            case 15:
                return androidx.compose.animation.V.d(AbstractC0240f.r(700, 0, null, 6), 2);
            case 16:
                return androidx.compose.animation.V.c(AbstractC0240f.r(700, 0, null, 6), 2);
            case 17:
                return ((C1291m) obj).f;
            case 18:
                return androidx.compose.animation.V.d(AbstractC0240f.r(700, 0, null, 6), 2);
            case 19:
                androidx.lifecycle.viewmodel.c initializer = (androidx.lifecycle.viewmodel.c) obj;
                Intrinsics.checkNotNullParameter(initializer, "$this$initializer");
                return new androidx.navigation.internal.b(p0.c(initializer));
            case 20:
                L navOptions2 = (L) obj;
                Intrinsics.checkNotNullParameter(navOptions2, "$this$navOptions");
                navOptions2.c = true;
                return Unit.a;
            case 21:
                B destination = (B) obj;
                Intrinsics.checkNotNullParameter(destination, "destination");
                D d = destination.c;
                if (d == null || d.f.b != destination.b.c) {
                    return null;
                }
                return d;
            case EventType.WINDOW_STATE /* 22 */:
                B destination2 = (B) obj;
                Intrinsics.checkNotNullParameter(destination2, "destination");
                D d2 = destination2.c;
                if (d2 == null || d2.f.b != destination2.b.c) {
                    return null;
                }
                return d2;
            case EventType.AUDIO /* 23 */:
                B it8 = (B) obj;
                Intrinsics.checkNotNullParameter(it8, "it");
                return Integer.valueOf(it8.b.c);
            case EventType.VIDEO /* 24 */:
                return (coil3.compose.h) obj;
            case EventType.SUBS /* 25 */:
                return Unit.a;
            case EventType.CDN /* 26 */:
                return com.braze.triggers.managers.a.a((File) obj);
            case 27:
                io.ktor.client.plugins.J install = (io.ktor.client.plugins.J) obj;
                Intrinsics.checkNotNullParameter(install, "$this$install");
                install.getClass();
                com.perimeterx.mobile_sdk.api_data.h block = new com.perimeterx.mobile_sdk.api_data.h(i3);
                Intrinsics.checkNotNullParameter(block, "block");
                install.f = SubsamplingScaleImageView.TILE_SIZE_AUTO;
                Intrinsics.checkNotNullParameter(block, "<set-?>");
                install.b = block;
                com.perimeterx.mobile_sdk.api_data.h block2 = new com.perimeterx.mobile_sdk.api_data.h(i2);
                Intrinsics.checkNotNullParameter(block2, "block");
                Intrinsics.checkNotNullParameter(block2, "<set-?>");
                install.b = block2;
                androidx.navigation.compose.x block3 = new androidx.navigation.compose.x(i);
                Intrinsics.checkNotNullParameter(block3, "block");
                install.d = block3;
                androidx.navigation.compose.x block4 = new androidx.navigation.compose.x(i3);
                Intrinsics.checkNotNullParameter(block4, "block");
                com.quizlet.features.questiontypes.written.ui.f fVar = new com.quizlet.features.questiontypes.written.ui.f(block4, i);
                Intrinsics.checkNotNullParameter(fVar, "<set-?>");
                install.c = fVar;
                return Unit.a;
            case 28:
                io.ktor.client.plugins.S install2 = (io.ktor.client.plugins.S) obj;
                Intrinsics.checkNotNullParameter(install2, "$this$install");
                install2.a = SubsamplingScaleImageView.TILE_SIZE_AUTO;
                return Unit.a;
            default:
                com.quizlet.ads.data.g it9 = (com.quizlet.ads.data.g) obj;
                List list = com.quizlet.ads.viewmodel.a.k;
                Intrinsics.checkNotNullParameter(it9, "it");
                return (com.quizlet.ads.data.f) it9;
        }
    }
}
