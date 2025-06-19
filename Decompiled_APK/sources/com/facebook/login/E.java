package com.facebook.login;

import android.content.Context;
import android.content.Intent;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.ImageView;
import android.widget.ProgressBar;
import com.bumptech.glide.Glide;
import com.facebook.FacebookException;
import com.facebook.FacebookRequestError;
import com.facebook.FacebookServiceException;
import com.facebook.login.LoginClient;
import com.google.firebase.messaging.AbstractServiceC3969f;
import com.google.firebase.perf.session.PerfSession;
import com.google.firebase.perf.session.SessionManager;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.perimeterx.mobile_sdk.PerimeterXDelegate;
import com.pubmatic.sdk.video.c;
import com.quizlet.db.data.models.persisted.DBAnswer;
import com.quizlet.db.data.models.persisted.DBGroup;
import com.quizlet.db.data.models.persisted.DBSession;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.quizletandroid.databinding.C4608l;
import com.quizlet.quizletandroid.ui.studymodes.write.WriteModeActivity;
import com.skydoves.balloon.Balloon;
import com.skydoves.balloon.BalloonPlacement;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Random;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONObject;
import retrofit2.C5187l;
import retrofit2.InterfaceC5182g;
import retrofit2.K;

/* loaded from: classes.dex */
public final /* synthetic */ class E implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;

    public /* synthetic */ E(ImageView imageView, String str, int i, String str2) {
        this.a = 8;
        this.b = imageView;
        this.c = str;
        this.d = str2;
    }

    @Override // java.lang.Runnable
    public final void run() throws Throwable {
        JSONObject jSONObjectOptJSONObject;
        switch (this.a) {
            case 0:
                NativeAppLoginMethodHandler this$0 = (NativeAppLoginMethodHandler) this.b;
                Intrinsics.checkNotNullParameter(this$0, "this$0");
                LoginClient.Request request = (LoginClient.Request) this.c;
                Intrinsics.checkNotNullParameter(request, "$request");
                Bundle extras = (Bundle) this.d;
                Intrinsics.checkNotNullParameter(extras, "$extras");
                try {
                    this$0.j(request, extras);
                    this$0.q(request, extras);
                    return;
                } catch (FacebookServiceException e) {
                    FacebookRequestError facebookRequestError = e.b;
                    this$0.p(request, facebookRequestError.d, facebookRequestError.a(), String.valueOf(facebookRequestError.b));
                    return;
                } catch (FacebookException e2) {
                    this$0.p(request, null, e2.getMessage(), null);
                    return;
                }
            case 1:
                String str = (String) this.c;
                String str2 = (String) this.d;
                com.google.firebase.crashlytics.internal.common.m mVar = ((com.google.firebase.crashlytics.internal.common.q) this.b).g;
                mVar.getClass();
                try {
                    ((androidx.browser.customtabs.k) mVar.d.d).i(str, str2);
                    return;
                } catch (IllegalArgumentException e3) {
                    Context context = mVar.a;
                    if (context != null && (context.getApplicationInfo().flags & 2) != 0) {
                        throw e3;
                    }
                    Log.e("FirebaseCrashlytics", "Attempting to set custom attribute with null key, ignoring.", null);
                    return;
                }
            case 2:
                Intent intent = (Intent) this.c;
                com.google.android.gms.tasks.f fVar = (com.google.android.gms.tasks.f) this.d;
                AbstractServiceC3969f abstractServiceC3969f = (AbstractServiceC3969f) this.b;
                abstractServiceC3969f.getClass();
                try {
                    abstractServiceC3969f.handleIntent(intent);
                    return;
                } finally {
                    fVar.b(null);
                }
            case 3:
                ((SessionManager) this.b).lambda$setApplicationContext$0((Context) this.c, (PerfSession) this.d);
                return;
            case 4:
                com.google.firebase.perf.transport.f fVar2 = (com.google.firebase.perf.transport.f) this.b;
                fVar2.getClass();
                com.google.firebase.perf.v1.u uVarC = com.google.firebase.perf.v1.v.C();
                uVarC.k();
                com.google.firebase.perf.v1.v.x((com.google.firebase.perf.v1.v) uVarC.b, (com.google.firebase.perf.v1.o) this.c);
                fVar2.d(uVarC, (com.google.firebase.perf.v1.i) this.d);
                return;
            case 5:
                com.google.firebase.perf.transport.f fVar3 = (com.google.firebase.perf.transport.f) this.b;
                fVar3.getClass();
                com.google.firebase.perf.v1.u uVarC2 = com.google.firebase.perf.v1.v.C();
                uVarC2.k();
                com.google.firebase.perf.v1.v.y((com.google.firebase.perf.v1.v) uVarC2.b, (com.google.firebase.perf.v1.E) this.c);
                fVar3.d(uVarC2, (com.google.firebase.perf.v1.i) this.d);
                return;
            case 6:
                com.google.firebase.perf.transport.f fVar4 = (com.google.firebase.perf.transport.f) this.b;
                fVar4.getClass();
                com.google.firebase.perf.v1.u uVarC3 = com.google.firebase.perf.v1.v.C();
                uVarC3.k();
                com.google.firebase.perf.v1.v.z((com.google.firebase.perf.v1.v) uVarC3.b, (com.google.firebase.perf.v1.t) this.c);
                fVar4.d(uVarC3, (com.google.firebase.perf.v1.i) this.d);
                return;
            case 7:
                com.google.firebase.remoteconfig.d dVar = (com.google.firebase.remoteconfig.d) this.b;
                String str3 = (String) this.c;
                com.google.firebase.remoteconfig.internal.c cVar = (com.google.firebase.remoteconfig.internal.c) this.d;
                androidx.work.impl.model.e eVar = dVar.a;
                com.google.firebase.analytics.connector.b bVar = (com.google.firebase.analytics.connector.b) ((com.google.firebase.inject.b) eVar.b).get();
                if (bVar == null) {
                    return;
                }
                JSONObject jSONObject = cVar.e;
                if (jSONObject.length() < 1) {
                    return;
                }
                JSONObject jSONObject2 = cVar.b;
                if (jSONObject2.length() >= 1 && (jSONObjectOptJSONObject = jSONObject.optJSONObject(str3)) != null) {
                    String strOptString = jSONObjectOptJSONObject.optString("choiceId");
                    if (strOptString.isEmpty()) {
                        return;
                    }
                    synchronized (((Map) eVar.c)) {
                        try {
                            if (!strOptString.equals(((Map) eVar.c).get(str3))) {
                                ((Map) eVar.c).put(str3, strOptString);
                                Bundle bundle = new Bundle();
                                bundle.putString("arm_key", str3);
                                bundle.putString("arm_value", jSONObject2.optString(str3));
                                bundle.putString("personalization_id", jSONObjectOptJSONObject.optString("personalizationId"));
                                bundle.putInt("arm_index", jSONObjectOptJSONObject.optInt("armIndex", -1));
                                bundle.putString(DBGroup.TABLE_NAME, jSONObjectOptJSONObject.optString(DBGroup.TABLE_NAME));
                                com.google.firebase.analytics.connector.c cVar2 = (com.google.firebase.analytics.connector.c) bVar;
                                cVar2.a("fp", "personalization_assignment", bundle);
                                Bundle bundle2 = new Bundle();
                                bundle2.putString("_fpid", strOptString);
                                cVar2.a("fp", "_fpc", bundle2);
                            }
                        } finally {
                        }
                    }
                    return;
                }
                return;
            case 8:
                ImageView this_loadLogo = (ImageView) this.b;
                Intrinsics.checkNotNullParameter(this_loadLogo, "$this_loadLogo");
                String navigatedFrom = (String) this.d;
                Intrinsics.checkNotNullParameter(navigatedFrom, "$navigatedFrom");
                String str4 = (String) this.c;
                com.onetrust.otpublishers.headless.UI.extensions.a aVar = new com.onetrust.otpublishers.headless.UI.extensions.a(0, navigatedFrom, str4);
                try {
                    com.bumptech.glide.m mVarD = Glide.d(this_loadLogo);
                    mVarD.getClass();
                    com.bumptech.glide.k kVarD = new com.bumptech.glide.k(mVarD.a, mVarD, Drawable.class, mVarD.b).D(str4);
                    kVarD.getClass();
                    ((com.bumptech.glide.k) kVarD.m(com.bumptech.glide.load.resource.bitmap.m.b, new com.bumptech.glide.load.resource.bitmap.t(), true)).b(new com.bumptech.glide.request.f().o(com.bumptech.glide.load.model.stream.a.b, Integer.valueOf(c.a.DEFAULT_MEDIA_URI_TIMEOUT))).B(aVar).z(this_loadLogo);
                    return;
                } catch (Exception e4) {
                    OTLogger.c("OneTrust", 3, "error on showing " + navigatedFrom + " logo, " + e4);
                    return;
                }
            case 9:
                PerimeterXDelegate perimeterXDelegate = (PerimeterXDelegate) this.b;
                if (perimeterXDelegate != null) {
                    perimeterXDelegate.perimeterxRequestBlockedHandler((String) this.c, (String) this.d);
                    return;
                }
                return;
            case 10:
                PerimeterXDelegate perimeterXDelegate2 = (PerimeterXDelegate) this.b;
                if (perimeterXDelegate2 != null) {
                    perimeterXDelegate2.perimeterxHeadersWereUpdated((LinkedHashMap) this.c, (String) this.d);
                    return;
                }
                return;
            case 11:
                WriteModeActivity writeModeActivity = (WriteModeActivity) this.b;
                writeModeActivity.getClass();
                DBSession dBSession = (DBSession) this.c;
                if (dBSession.getEndedTimestampSeconds() <= 0) {
                    ArrayList arrayList = (ArrayList) this.d;
                    if (arrayList.size() < 7) {
                        timber.log.c.a.a("resumeRound", new Object[0]);
                        writeModeActivity.W.clear();
                        writeModeActivity.X.clear();
                        ((ProgressBar) ((C4608l) writeModeActivity.k).f.c).setVisibility(0);
                        Iterator it2 = arrayList.iterator();
                        while (it2.hasNext()) {
                            DBAnswer dBAnswer = (DBAnswer) it2.next();
                            writeModeActivity.V.add(0, (DBTerm) writeModeActivity.c1.get(Long.valueOf(dBAnswer.getTermId())));
                            if (com.bumptech.glide.b.c(dBAnswer.getCorrectness())) {
                                writeModeActivity.X.add((DBTerm) writeModeActivity.c1.get(Long.valueOf(dBAnswer.getTermId())));
                            } else {
                                writeModeActivity.W.add((DBTerm) writeModeActivity.c1.get(Long.valueOf(dBAnswer.getTermId())));
                            }
                        }
                        Collections.shuffle(writeModeActivity.M, new Random(dBSession.getTimestamp()));
                        ArrayList arrayList2 = new ArrayList();
                        while (writeModeActivity.V.size() + arrayList2.size() < 7 && writeModeActivity.M.size() > 0) {
                            arrayList2.add((DBTerm) writeModeActivity.M.remove(0));
                        }
                        writeModeActivity.V.addAll(arrayList2);
                        writeModeActivity.f1 = arrayList.size() - 1;
                        writeModeActivity.S();
                        break;
                    } else {
                        Iterator it3 = arrayList.iterator();
                        while (it3.hasNext()) {
                            DBAnswer dBAnswer2 = (DBAnswer) it3.next();
                            if (!com.bumptech.glide.b.c(dBAnswer2.getCorrectness())) {
                                writeModeActivity.M.add(0, (DBTerm) writeModeActivity.c1.get(Long.valueOf(dBAnswer2.getTermId())));
                            }
                        }
                        writeModeActivity.Y(dBSession);
                    }
                } else {
                    writeModeActivity.c0(writeModeActivity.Z, writeModeActivity.c1);
                }
                com.quizlet.features.infra.basestudy.data.models.dataproviders.a aVar2 = writeModeActivity.u;
                if (aVar2 == null) {
                    return;
                }
                DBSession dBSession2 = aVar2.C;
                if (dBSession2 == null || !dBSession2.hasEnded()) {
                    ((ImageView) ((C4608l) writeModeActivity.k).f.e).setVisibility(0);
                    return;
                } else {
                    ((ProgressBar) ((C4608l) writeModeActivity.k).f.c).setVisibility(8);
                    ((ImageView) ((C4608l) writeModeActivity.k).f.e).setVisibility(8);
                    return;
                }
            case 12:
                Balloon.initializeArrow$lambda$7$lambda$6((Balloon) this.b, (View) this.c, (ImageView) this.d);
                return;
            case 13:
                Balloon.show$lambda$34((Balloon) this.b, (View) this.c, (BalloonPlacement) this.d);
                return;
            case 14:
                C5187l c5187l = (C5187l) ((com.quizlet.remote.model.report.c) this.b).b;
                boolean zC = c5187l.b.C();
                InterfaceC5182g interfaceC5182g = (InterfaceC5182g) this.c;
                if (zC) {
                    interfaceC5182g.f(c5187l, new IOException("Canceled"));
                    return;
                } else {
                    interfaceC5182g.k(c5187l, (K) this.d);
                    return;
                }
            default:
                ((InterfaceC5182g) this.c).f((C5187l) ((com.quizlet.remote.model.report.c) this.b).b, (Throwable) this.d);
                return;
        }
    }

    public /* synthetic */ E(Object obj, Object obj2, Object obj3, int i) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
        this.d = obj3;
    }
}
