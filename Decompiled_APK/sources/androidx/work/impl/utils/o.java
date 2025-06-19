package androidx.work.impl.utils;

import android.content.Context;
import android.content.Intent;
import android.os.PowerManager;
import androidx.compose.animation.core.C0238e;
import androidx.compose.material3.C0624g4;
import androidx.compose.material3.EnumC0630h4;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.work.C1442p;
import androidx.work.impl.C1433e;
import androidx.work.impl.F;
import androidx.work.impl.foreground.SystemForegroundService;
import androidx.work.z;
import assistantMode.enums.y;
import com.braze.Braze;
import com.braze.models.outgoing.BrazeProperties;
import com.google.android.gms.internal.mlkit_vision_camera.A2;
import com.quizlet.assembly.compose.buttons.c0;
import com.quizlet.data.interactor.achievements.f;
import com.quizlet.data.model.C4123e0;
import com.quizlet.generated.enums.y1;
import com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.LearnSettingsUpdateData;
import io.reactivex.rxjava3.core.p;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.UUID;
import kotlin.Unit;
import kotlin.collections.G;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.J;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;

/* loaded from: classes.dex */
public final /* synthetic */ class o implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;

    public /* synthetic */ o(Object obj, Object obj2, Object obj3, Object obj4, int i) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
        this.d = obj3;
        this.e = obj4;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                p pVar = (p) this.b;
                UUID uuid = (UUID) this.c;
                C1442p c1442p = (C1442p) this.d;
                Context context = (Context) this.e;
                pVar.getClass();
                String string = uuid.toString();
                androidx.work.impl.model.q qVarO = pVar.c.o(string);
                if (qVarO == null || qVarO.b.a()) {
                    throw new IllegalStateException("Calls to setForegroundAsync() must complete before a ListenableWorker signals completion of work by returning an instance of Result.");
                }
                C1433e c1433e = pVar.b;
                synchronized (c1433e.k) {
                    try {
                        z.c().d(C1433e.l, "Moving WorkSpec (" + string + ") to the foreground");
                        F f = (F) c1433e.g.remove(string);
                        if (f != null) {
                            if (c1433e.a == null) {
                                PowerManager.WakeLock wakeLockA = k.a(c1433e.b, "ProcessorForegroundLck");
                                c1433e.a = wakeLockA;
                                wakeLockA.acquire();
                            }
                            c1433e.f.put(string, f);
                            c1433e.b.startForegroundService(androidx.work.impl.foreground.a.a(c1433e.b, A2.a(f.a), c1442p));
                        }
                    } catch (Throwable th) {
                        throw th;
                    }
                }
                androidx.work.impl.model.j jVarA = A2.a(qVarO);
                String str = androidx.work.impl.foreground.a.j;
                Intent intent = new Intent(context, (Class<?>) SystemForegroundService.class);
                intent.setAction("ACTION_NOTIFY");
                intent.putExtra("KEY_NOTIFICATION_ID", c1442p.a);
                intent.putExtra("KEY_FOREGROUND_SERVICE_TYPE", c1442p.b);
                intent.putExtra("KEY_NOTIFICATION", c1442p.c);
                intent.putExtra("KEY_WORKSPEC_ID", jVarA.a);
                intent.putExtra("KEY_GENERATION", jVarA.b);
                context.startService(intent);
                return null;
            case 1:
                return Braze.logCustomEvent$lambda$50((Braze) this.b, (String) this.c, (BrazeProperties) this.d, (BrazeProperties) this.e);
            case 2:
                return Braze.logPushNotificationActionClicked$lambda$67((String) this.b, (Braze) this.c, (String) this.d, (String) this.e);
            case 3:
                E.A((C) this.b, null, null, new c0((Function1) this.c, (C0238e) this.d, (InterfaceC0773a0) this.e, null), 3);
                return Unit.a;
            case 4:
                final com.quizlet.data.repository.folderset.c cVar = (com.quizlet.data.repository.folderset.c) ((com.quizlet.data.repository.widget.b) this.b).b;
                final Collection setIds = (Collection) this.c;
                Intrinsics.checkNotNullParameter(setIds, "setIds");
                final List originalFolderSets = (List) this.d;
                Intrinsics.checkNotNullParameter(originalFolderSets, "originalFolderSets");
                final LinkedHashSet newFolderIds = (LinkedHashSet) this.e;
                Intrinsics.checkNotNullParameter(newFolderIds, "newFolderIds");
                io.reactivex.rxjava3.internal.operators.flowable.b bVar = new io.reactivex.rxjava3.internal.operators.flowable.b(new io.reactivex.rxjava3.functions.j() { // from class: com.quizlet.data.repository.folderset.a
                    @Override // io.reactivex.rxjava3.functions.j
                    public final Object get() {
                        List list = originalFolderSets;
                        ArrayList arrayList = new ArrayList(kotlin.collections.C.q(list, 10));
                        Iterator it2 = list.iterator();
                        while (it2.hasNext()) {
                            arrayList.add(Long.valueOf(((C4123e0) it2.next()).c));
                        }
                        LinkedHashSet linkedHashSet = newFolderIds;
                        ArrayList arrayList2 = new ArrayList();
                        for (Object obj : linkedHashSet) {
                            if (!arrayList.contains(Long.valueOf(((Number) obj).longValue()))) {
                                arrayList2.add(obj);
                            }
                        }
                        c cVar2 = cVar;
                        Collection collection = setIds;
                        ArrayList arrayList3 = new ArrayList();
                        Iterator it3 = collection.iterator();
                        while (it3.hasNext()) {
                            long jLongValue = ((Number) it3.next()).longValue();
                            ArrayList arrayList4 = new ArrayList(kotlin.collections.C.q(arrayList2, 10));
                            Iterator it4 = arrayList2.iterator();
                            while (it4.hasNext()) {
                                long jLongValue2 = ((Number) it4.next()).longValue();
                                long jA = com.quizlet.time.b.a();
                                arrayList4.add(new C4123e0(0L, jLongValue, jLongValue2, 0L, Boolean.FALSE, Long.valueOf(jA), com.quizlet.time.b.a(), true));
                            }
                            G.u(arrayList3, arrayList4);
                        }
                        io.reactivex.rxjava3.internal.operators.flowable.b bVarF = p.f(arrayList3);
                        Intrinsics.checkNotNullExpressionValue(bVarF, "just(...)");
                        ArrayList arrayList5 = new ArrayList();
                        for (Object obj2 : list) {
                            if (!linkedHashSet.contains(Long.valueOf(((C4123e0) obj2).c))) {
                                arrayList5.add(obj2);
                            }
                        }
                        ArrayList arrayList6 = new ArrayList(kotlin.collections.C.q(arrayList5, 10));
                        Iterator it5 = arrayList5.iterator();
                        while (it5.hasNext()) {
                            C4123e0 c4123e0 = (C4123e0) it5.next();
                            Boolean bool = Boolean.TRUE;
                            arrayList6.add(new C4123e0(c4123e0.a, c4123e0.b, c4123e0.c, c4123e0.d, bool, c4123e0.f, c4123e0.g, true));
                        }
                        io.reactivex.rxjava3.internal.operators.flowable.b bVarF2 = p.f(arrayList6);
                        Intrinsics.checkNotNullExpressionValue(bVarF2, "just(...)");
                        return p.p(bVarF, bVarF2, b.d).e(new f(cVar2, 8));
                    }
                }, 4);
                Intrinsics.checkNotNullExpressionValue(bVar, "defer(...)");
                return bVar;
            case 5:
                return new C0624g4((EnumC0630h4) this.b, (androidx.compose.ui.unit.b) this.c, (Function1) this.d, (Function1) this.e);
            case 6:
                com.quizlet.features.infra.folder.save.viewmodel.c cVar2 = (com.quizlet.features.infra.folder.save.viewmodel.c) this.b;
                y1 y1Var = cVar2.d;
                if (y1Var != null) {
                    String str2 = cVar2.e;
                    if (str2.length() != 0) {
                        cVar2.c.B(str2, y1Var);
                    }
                }
                ((com.quizlet.features.infra.folder.menu.viewmodel.n) this.c).o((String) this.d, (y1) this.e);
                return Unit.a;
            case 7:
                J j = (J) this.b;
                if (((com.quizlet.features.questiontypes.written.ui.o) j.a) != null) {
                    String str3 = (String) ((InterfaceC0773a0) this.d).getValue();
                    Boolean bool = (Boolean) ((InterfaceC0773a0) this.e).getValue();
                    bool.booleanValue();
                    ((kotlin.jvm.functions.c) this.c).invoke(str3, bool, j.a);
                }
                return Unit.a;
            case 8:
                com.quizlet.studiablemodels.assistantMode.a aVar = ((com.quizlet.learn.data.onboarding.m) this.b).a;
                ((InterfaceC0773a0) this.d).setValue(aVar);
                ((Function1) this.c).invoke(new com.quizlet.learn.data.onboarding.f(aVar, (y) ((InterfaceC0773a0) this.e).getValue()));
                return Unit.a;
            case 9:
                com.quizlet.learn.data.onboarding.u uVar = (com.quizlet.learn.data.onboarding.u) this.b;
                InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) this.d;
                y yVar = uVar.a;
                interfaceC0773a0.setValue(yVar);
                ((Function1) this.c).invoke(new com.quizlet.learn.data.onboarding.f((com.quizlet.studiablemodels.assistantMode.a) ((InterfaceC0773a0) this.e).getValue(), yVar));
                return Unit.a;
            case 10:
                ((kotlin.jvm.functions.c) this.b).invoke((String) ((InterfaceC0773a0) this.c).getValue(), (String) ((InterfaceC0773a0) this.d).getValue(), Boolean.valueOf(!((Boolean) ((InterfaceC0773a0) this.e).getValue()).booleanValue()));
                return Unit.a;
            default:
                LearnSettingsUpdateData learnSettingsUpdateData = (LearnSettingsUpdateData) this.c;
                ((Function1) this.b).invoke(LearnSettingsUpdateData.a(learnSettingsUpdateData, false, false, false, false, false, false, false, false, false, null, 3071));
                ((Function1) this.d).invoke(new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.g(learnSettingsUpdateData));
                ((Function0) this.e).invoke();
                return Unit.a;
        }
    }
}
