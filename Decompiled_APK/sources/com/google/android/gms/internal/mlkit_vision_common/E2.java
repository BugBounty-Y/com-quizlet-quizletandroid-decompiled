package com.google.android.gms.internal.mlkit_vision_common;

import android.content.SharedPreferences;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.facebook.internal.C1563s;
import com.facebook.internal.EnumC1562q;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;

/* loaded from: classes2.dex */
public abstract class E2 {
    public static boolean a;

    public static final void a(com.quizlet.themes.nighttheme.a aVar, com.google.mlkit.vision.documentscanner.internal.c cVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1363867);
        if ((((c0814p.f(aVar) ? 4 : 2) | i | (c0814p.f(cVar) ? 32 : 16)) & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.S();
            if ((i & 1) != 0 && !c0814p.w()) {
                c0814p.Q();
            }
            c0814p.q();
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i2 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, nVar);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, bA, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i2))) {
                android.support.v4.media.session.a.z(i2, c0814p, i2, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            M2.c(AbstractC3106b5.d(c0814p, R.string.appearance_title), null, c0814p, 0);
            com.quizlet.themes.m.g.u();
            com.google.android.gms.internal.mlkit_vision_document_scanner.R4.a(AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.g, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), null, 0L, 0L, 0L, null, false, null, null, null, androidx.compose.runtime.internal.e.e(1496269163, new com.quizlet.features.practicetest.results.i(9, aVar, cVar), c0814p), c0814p, 0, 1022);
            c0814p = c0814p;
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questionnaire.screens.d(aVar, cVar, i, 5);
        }
    }

    public static final void b(Throwable th) {
        HashMap map;
        EnumC1562q feature;
        if (!a || th == null) {
            return;
        }
        HashSet hashSet = new HashSet();
        StackTraceElement[] stackTrace = th.getStackTrace();
        Intrinsics.checkNotNullExpressionValue(stackTrace, "e.stackTrace");
        for (StackTraceElement stackTraceElement : stackTrace) {
            String className = stackTraceElement.getClassName();
            Intrinsics.checkNotNullExpressionValue(className, "it.className");
            C1563s c1563s = C1563s.a;
            Intrinsics.checkNotNullParameter(className, "className");
            synchronized (C1563s.a) {
                map = C1563s.b;
                if (map.isEmpty()) {
                    map.put(EnumC1562q.AAM, new String[]{"com.facebook.appevents.aam."});
                    map.put(EnumC1562q.CodelessEvents, new String[]{"com.facebook.appevents.codeless."});
                    map.put(EnumC1562q.CloudBridge, new String[]{"com.facebook.appevents.cloudbridge."});
                    map.put(EnumC1562q.ErrorReport, new String[]{"com.facebook.internal.instrument.errorreport."});
                    map.put(EnumC1562q.AnrReport, new String[]{"com.facebook.internal.instrument.anrreport."});
                    map.put(EnumC1562q.PrivacyProtection, new String[]{"com.facebook.appevents.ml."});
                    map.put(EnumC1562q.SuggestedEvents, new String[]{"com.facebook.appevents.suggestedevents."});
                    map.put(EnumC1562q.RestrictiveDataFiltering, new String[]{"com.facebook.appevents.restrictivedatafilter.RestrictiveDataManager"});
                    map.put(EnumC1562q.IntelligentIntegrity, new String[]{"com.facebook.appevents.integrity.IntegrityManager"});
                    map.put(EnumC1562q.ProtectedMode, new String[]{"com.facebook.appevents.integrity.ProtectedModeManager"});
                    map.put(EnumC1562q.MACARuleMatching, new String[]{"com.facebook.appevents.integrity.MACARuleMatchingManager"});
                    map.put(EnumC1562q.BlocklistEvents, new String[]{"com.facebook.appevents.integrity.BlocklistEventsManager"});
                    map.put(EnumC1562q.FilterRedactedEvents, new String[]{"com.facebook.appevents.integrity.RedactedEventsManager"});
                    map.put(EnumC1562q.FilterSensitiveParams, new String[]{"com.facebook.appevents.integrity.SensitiveParamsManager"});
                    map.put(EnumC1562q.EventDeactivation, new String[]{"com.facebook.appevents.eventdeactivation."});
                    map.put(EnumC1562q.OnDeviceEventProcessing, new String[]{"com.facebook.appevents.ondeviceprocessing."});
                    map.put(EnumC1562q.IapLogging, new String[]{"com.facebook.appevents.iap."});
                    map.put(EnumC1562q.Monitoring, new String[]{"com.facebook.internal.logging.monitor"});
                    map.put(EnumC1562q.GPSARATriggers, new String[]{"com.facebook.appevents.gps.ara.GpsARAManager"});
                    map.put(EnumC1562q.GPSPACAProcessing, new String[]{"com.facebook.appevents.gps.pa.PACustomAudienceClient"});
                    map.put(EnumC1562q.GPSTopicsObservation, new String[]{"com.facebook.appevents.gps.topics.GpsTopicsManager"});
                }
            }
            Iterator it2 = map.entrySet().iterator();
            while (true) {
                if (!it2.hasNext()) {
                    feature = EnumC1562q.Unknown;
                    break;
                }
                Map.Entry entry = (Map.Entry) it2.next();
                feature = (EnumC1562q) entry.getKey();
                for (String str : (String[]) entry.getValue()) {
                    if (kotlin.text.D.r(className, str, false)) {
                        break;
                    }
                }
            }
            if (feature != EnumC1562q.Unknown) {
                Intrinsics.checkNotNullParameter(feature, "feature");
                SharedPreferences.Editor editorEdit = com.facebook.o.a().getSharedPreferences("com.facebook.internal.FEATURE_MANAGER", 0).edit();
                feature.getClass();
                editorEdit.putString("FBSDKFeature" + feature, "18.0.3").apply();
                hashSet.add(feature.toString());
            }
        }
        com.facebook.o oVar = com.facebook.o.a;
        if (!com.facebook.B.c() || hashSet.isEmpty()) {
            return;
        }
        JSONArray features = new JSONArray((Collection) hashSet);
        Intrinsics.checkNotNullParameter(features, "features");
        com.facebook.internal.instrument.c cVar = new com.facebook.internal.instrument.c();
        cVar.b = com.facebook.internal.instrument.a.b;
        Long lValueOf = Long.valueOf(System.currentTimeMillis() / 1000);
        cVar.g = lValueOf;
        cVar.c = features;
        StringBuffer stringBuffer = new StringBuffer("analysis_log_");
        stringBuffer.append(String.valueOf(lValueOf));
        stringBuffer.append(".json");
        String string = stringBuffer.toString();
        Intrinsics.checkNotNullExpressionValue(string, "StringBuffer()\n         …)\n            .toString()");
        cVar.a = string;
        cVar.b();
    }
}
