package com.quizlet.quizletandroid.ui.deeplinkinterstitial;

import android.content.ComponentName;
import android.content.Intent;
import android.net.Uri;
import android.widget.Toast;
import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_barcode.T;
import com.quizlet.eventlogger.features.deeplink.DeepLinkEventLog;
import com.quizlet.eventlogger.features.deeplink.DeepLinkEventLogger;
import com.quizlet.features.emailconfirmation.ui.activities.EmailConfirmationActivity;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.managers.deeplinks.B;
import com.quizlet.quizletandroid.managers.deeplinks.C;
import com.quizlet.quizletandroid.ui.deeplinkinterstitial.DeepLinkInterstitialActivity;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes3.dex */
public final class b extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ DeepLinkInterstitialActivity k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(DeepLinkInterstitialActivity deepLinkInterstitialActivity, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = deepLinkInterstitialActivity;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        b bVar = new b(this.k, hVar);
        bVar.j = obj;
        return bVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((a) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        boolean z;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        a aVar2 = (a) this.j;
        if (aVar2 != null) {
            String str = DeepLinkInterstitialActivity.s;
            DeepLinkInterstitialActivity deepLinkInterstitialActivity = this.k;
            com.quizlet.infra.androidcontracts.deeplink.a deeplink = aVar2.a;
            boolean z2 = deeplink instanceof C;
            com.quizlet.data.repository.folderwithcreatorinclass.e eVar = deepLinkInterstitialActivity.r;
            if (z2) {
                C c = (C) deeplink;
                B b = c.a;
                int iOrdinal = b.ordinal();
                if (iOrdinal == 0 || iOrdinal == 1) {
                    Toast.makeText(deepLinkInterstitialActivity, R.string.join_link_error, 1).show();
                } else if (iOrdinal != 2) {
                    throw new NoWhenBranchMatchedException();
                }
                i iVar = (i) eVar.getValue();
                Uri data = deepLinkInterstitialActivity.getIntent().getData();
                String string = data != null ? data.toString() : null;
                Uri referrer = deepLinkInterstitialActivity.getReferrer();
                iVar.A(c, string, referrer != null ? referrer.toString() : null, b.toString());
            }
            com.quizlet.quizletandroid.managers.deeplinks.h hVar = deepLinkInterstitialActivity.q;
            if (hVar == null) {
                Intrinsics.m("uriAllowlistedChecker");
                throw null;
            }
            Intent[] intentArrC = deeplink.c(deepLinkInterstitialActivity, hVar);
            if (intentArrC.length == 0) {
                timber.log.a aVar3 = timber.log.c.a;
                Intrinsics.checkNotNullParameter(deeplink, "deepLink");
                aVar3.e(new DeepLinkInterstitialActivity.DeepLinkException("Failed to handle deep link: " + deeplink));
                Toast.makeText(deepLinkInterstitialActivity, R.string.deeplink_error_toast, 1).show();
                i iVar2 = (i) eVar.getValue();
                Uri data2 = deepLinkInterstitialActivity.getIntent().getData();
                String string2 = data2 != null ? data2.toString() : null;
                Uri referrer2 = deepLinkInterstitialActivity.getReferrer();
                iVar2.A(deeplink, string2, referrer2 != null ? referrer2.toString() : null, null);
                deepLinkInterstitialActivity.finish();
            } else {
                for (Intent intent : intentArrC) {
                    intent.addFlags(65536);
                }
                if (!aVar2.b || deeplink.b()) {
                    deepLinkInterstitialActivity.startActivities(intentArrC);
                    z = false;
                } else {
                    String str2 = EmailConfirmationActivity.r;
                    Intent intentB = T.b(deepLinkInterstitialActivity, intentArrC);
                    intentB.addFlags(65536);
                    deepLinkInterstitialActivity.startActivity(intentB);
                    z = true;
                }
                i iVar3 = (i) eVar.getValue();
                Uri data3 = deepLinkInterstitialActivity.getIntent().getData();
                String string3 = data3 != null ? data3.toString() : null;
                Uri referrer3 = deepLinkInterstitialActivity.getReferrer();
                String string4 = referrer3 != null ? referrer3.toString() : null;
                ArrayList arrayList = new ArrayList(intentArrC.length);
                for (Intent intent2 : intentArrC) {
                    arrayList.add(intent2.resolveActivity(deepLinkInterstitialActivity.getPackageManager()));
                }
                ArrayList activityTargets = new ArrayList(kotlin.collections.C.q(arrayList, 10));
                Iterator it2 = arrayList.iterator();
                while (it2.hasNext()) {
                    String shortClassName = ((ComponentName) it2.next()).getShortClassName();
                    Intrinsics.checkNotNullExpressionValue(shortClassName, "getShortClassName(...)");
                    activityTargets.add(StringsKt.c0(shortClassName, shortClassName, '.'));
                }
                iVar3.getClass();
                Intrinsics.checkNotNullParameter(deeplink, "deeplink");
                Intrinsics.checkNotNullParameter(activityTargets, "targets");
                String deepLinkType = deeplink.identity();
                DeepLinkEventLogger deepLinkEventLogger = iVar3.d;
                deepLinkEventLogger.getClass();
                Intrinsics.checkNotNullParameter(deepLinkType, "deepLinkType");
                Intrinsics.checkNotNullParameter(activityTargets, "activityTargets");
                DeepLinkEventLog.Companion companion = DeepLinkEventLog.b;
                androidx.navigation.internal.f fVar = new androidx.navigation.internal.f(deepLinkType, string3, string4, activityTargets, z);
                companion.getClass();
                deepLinkEventLogger.a(DeepLinkEventLog.Companion.a("deep_link_opened", fVar));
            }
        }
        return Unit.a;
    }
}
