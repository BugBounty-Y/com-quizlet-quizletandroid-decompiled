package androidx.work.impl;

import android.app.ActivityManager;
import android.content.Context;
import android.content.res.Resources;
import androidx.activity.L;
import androidx.activity.N;
import androidx.appcompat.app.ExecutorC0060p;
import androidx.appcompat.app.Q;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.V;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import androidx.lifecycle.J;
import androidx.work.C1422c;
import androidx.work.impl.background.systemjob.SystemJobService;
import com.quizlet.quizletandroid.R;
import java.io.File;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executor;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes.dex */
public abstract class t {
    public static final /* synthetic */ int a = 0;

    public static final void a(boolean z, Function0 function0, InterfaceC0806l interfaceC0806l, int i, int i2) {
        int i3;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-361453782);
        int i4 = i2 & 1;
        if (i4 != 0) {
            i3 = i | 6;
        } else if ((i & 6) == 0) {
            i3 = (c0814p.g(z) ? 4 : 2) | i;
        } else {
            i3 = i;
        }
        if ((i & 48) == 0) {
            i3 |= c0814p.h(function0) ? 32 : 16;
        }
        if ((i3 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            if (i4 != 0) {
                z = true;
            }
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D(function0, c0814p);
            Object objI = c0814p.I();
            V v = C0804k.a;
            if (objI == v) {
                objI = new androidx.activity.compose.i(interfaceC0773a0D, z);
                c0814p.i0(objI);
            }
            androidx.activity.compose.i iVar = (androidx.activity.compose.i) objI;
            boolean z2 = (i3 & 14) == 4;
            Object objI2 = c0814p.I();
            if (z2 || objI2 == v) {
                objI2 = new androidx.activity.compose.f(z, 0, iVar);
                c0814p.i0(objI2);
            }
            C0776c.i((Function0) objI2, c0814p);
            N nA = androidx.activity.compose.n.a(c0814p);
            if (nA == null) {
                throw new IllegalStateException("No OnBackPressedDispatcherOwner was provided via LocalOnBackPressedDispatcherOwner");
            }
            L onBackPressedDispatcher = nA.getOnBackPressedDispatcher();
            J j = (J) c0814p.j(AndroidCompositionLocals_androidKt.getLocalLifecycleOwner());
            boolean zH = c0814p.h(onBackPressedDispatcher) | c0814p.h(j);
            Object objI3 = c0814p.I();
            if (zH || objI3 == v) {
                objI3 = new androidx.activity.compose.g(onBackPressedDispatcher, j, iVar, 0);
                c0814p.i0(objI3);
            }
            C0776c.c(j, onBackPressedDispatcher, (Function1) objI3, c0814p);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.activity.compose.h(i, i2, function0, z);
        }
    }

    public static final File b(File parentDirectory, String fileExtension) throws IOException {
        Intrinsics.checkNotNullParameter(fileExtension, "fileExtension");
        Intrinsics.checkNotNullParameter(parentDirectory, "parentDirectory");
        String str = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
        Intrinsics.checkNotNullExpressionValue(str, "format(...)");
        File fileCreateTempFile = File.createTempFile(android.support.v4.media.session.a.B("IMG_", str, "_"), ".".concat(fileExtension), parentDirectory);
        Intrinsics.checkNotNullExpressionValue(fileCreateTempFile, "createTempFile(...)");
        return fileCreateTempFile;
    }

    public static final r c(Context p0, C1422c p1) throws Resources.NotFoundException, ClassNotFoundException {
        androidx.room.q qVar;
        androidx.room.r rVar;
        Iterator it2;
        boolean zContainsKey;
        int i = 5;
        Intrinsics.checkNotNullParameter(p0, "context");
        Intrinsics.checkNotNullParameter(p1, "configuration");
        androidx.work.impl.utils.taskexecutor.c workTaskExecutor = new androidx.work.impl.utils.taskexecutor.c(p1.c);
        Context context = p0.getApplicationContext();
        Intrinsics.checkNotNullExpressionValue(context, "context.applicationContext");
        ExecutorC0060p executor = workTaskExecutor.a;
        Intrinsics.checkNotNullExpressionValue(executor, "workTaskExecutor.serialTaskExecutor");
        boolean z = p0.getResources().getBoolean(R.bool.workmanager_test_configuration);
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(executor, "queryExecutor");
        androidx.work.B clock = p1.d;
        Intrinsics.checkNotNullParameter(clock, "clock");
        if (z) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(WorkDatabase.class, "klass");
            qVar = new androidx.room.q(context, null);
            qVar.i = true;
        } else {
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(WorkDatabase.class, "klass");
            if (StringsKt.O("androidx.work.workdb")) {
                throw new IllegalArgumentException("Cannot build a database with null or empty name. If you are trying to create an in memory database, use Room.inMemoryDatabaseBuilder");
            }
            androidx.room.q qVar2 = new androidx.room.q(context, "androidx.work.workdb");
            qVar2.h = new o(context);
            qVar = qVar2;
        }
        Intrinsics.checkNotNullParameter(executor, "executor");
        qVar.f = executor;
        C1429a callback = new C1429a(clock);
        Intrinsics.checkNotNullParameter(callback, "callback");
        ArrayList arrayList = qVar.c;
        arrayList.add(callback);
        qVar.a(C1431c.h);
        qVar.a(new C1434f(context, 2, 3));
        qVar.a(C1431c.i);
        qVar.a(C1431c.j);
        qVar.a(new C1434f(context, 5, 6));
        qVar.a(C1431c.k);
        qVar.a(C1431c.l);
        qVar.a(C1431c.m);
        qVar.a(new u(context));
        qVar.a(new C1434f(context, 10, 11));
        qVar.a(C1431c.d);
        qVar.a(C1431c.e);
        qVar.a(C1431c.f);
        qVar.a(C1431c.g);
        qVar.a(new C1434f(context, 21, 22));
        qVar.k = false;
        qVar.l = true;
        Executor executor2 = qVar.f;
        if (executor2 == null && qVar.g == null) {
            androidx.arch.core.executor.a aVar = androidx.arch.core.executor.b.c;
            qVar.g = aVar;
            qVar.f = aVar;
        } else if (executor2 != null && qVar.g == null) {
            qVar.g = executor2;
        } else if (executor2 == null) {
            qVar.f = qVar.g;
        }
        HashSet hashSet = qVar.p;
        LinkedHashSet linkedHashSet = qVar.o;
        if (hashSet != null) {
            Iterator it3 = hashSet.iterator();
            while (it3.hasNext()) {
                int iIntValue = ((Number) it3.next()).intValue();
                if (linkedHashSet.contains(Integer.valueOf(iIntValue))) {
                    throw new IllegalArgumentException(android.support.v4.media.session.a.f(iIntValue, "Inconsistency detected. A Migration was supplied to addMigration(Migration... migrations) that has a start or end version equal to a start version supplied to fallbackToDestructiveMigrationFrom(int... startVersions). Start version: ").toString());
                }
            }
        }
        androidx.sqlite.db.d eVar = qVar.h;
        if (eVar == null) {
            eVar = new com.google.android.material.shape.e(i);
        }
        androidx.sqlite.db.d dVar = eVar;
        if (qVar.m > 0) {
            if (qVar.b != null) {
                throw new IllegalArgumentException("Required value was null.");
            }
            throw new IllegalArgumentException("Cannot create auto-closing database for an in-memory database.");
        }
        boolean z2 = qVar.i;
        androidx.room.r rVar2 = qVar.j;
        rVar2.getClass();
        Context context2 = qVar.a;
        Intrinsics.checkNotNullParameter(context2, "context");
        androidx.room.r rVar3 = androidx.room.r.a;
        androidx.room.r rVar4 = androidx.room.r.c;
        if (rVar2 != rVar3) {
            rVar = rVar2;
        } else {
            Object systemService = context2.getSystemService("activity");
            ActivityManager activityManager = systemService instanceof ActivityManager ? (ActivityManager) systemService : null;
            if (activityManager != null) {
                Intrinsics.checkNotNullParameter(activityManager, "activityManager");
                if (!activityManager.isLowRamDevice()) {
                    rVar = rVar4;
                }
            }
            rVar2 = androidx.room.r.b;
            rVar = rVar2;
        }
        Executor executor3 = qVar.f;
        if (executor3 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        Executor executor4 = qVar.g;
        if (executor4 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        androidx.room.f configuration = new androidx.room.f(context2, qVar.b, dVar, qVar.n, arrayList, z2, rVar, executor3, executor4, qVar.k, qVar.l, linkedHashSet, qVar.d, qVar.e);
        Intrinsics.checkNotNullParameter(WorkDatabase.class, "klass");
        Intrinsics.checkNotNullParameter("_Impl", "suffix");
        Package r3 = WorkDatabase.class.getPackage();
        Intrinsics.d(r3);
        String fullPackage = r3.getName();
        String canonicalName = WorkDatabase.class.getCanonicalName();
        Intrinsics.d(canonicalName);
        Intrinsics.checkNotNullExpressionValue(fullPackage, "fullPackage");
        if (fullPackage.length() != 0) {
            canonicalName = canonicalName.substring(fullPackage.length() + 1);
            Intrinsics.checkNotNullExpressionValue(canonicalName, "this as java.lang.String).substring(startIndex)");
        }
        String str = kotlin.text.D.p(canonicalName, '.', '_') + "_Impl";
        try {
            Class<?> cls = Class.forName(fullPackage.length() == 0 ? str : fullPackage + '.' + str, true, WorkDatabase.class.getClassLoader());
            Intrinsics.e(cls, "null cannot be cast to non-null type java.lang.Class<T of androidx.room.Room.getGeneratedImplementation>");
            WorkDatabase p3 = (WorkDatabase) cls.getDeclaredConstructor(null).newInstance(null);
            p3.getClass();
            Intrinsics.checkNotNullParameter(configuration, "configuration");
            p3.d = p3.e(configuration);
            Set setI = p3.i();
            BitSet bitSet = new BitSet();
            Iterator it4 = setI.iterator();
            while (true) {
                boolean zHasNext = it4.hasNext();
                LinkedHashMap linkedHashMap = p3.h;
                ArrayList arrayList2 = configuration.n;
                if (zHasNext) {
                    Class cls2 = (Class) it4.next();
                    int size = arrayList2.size() - 1;
                    if (size >= 0) {
                        while (true) {
                            int i2 = size - 1;
                            if (cls2.isAssignableFrom(arrayList2.get(size).getClass())) {
                                bitSet.set(size);
                                break;
                            }
                            if (i2 < 0) {
                                break;
                            }
                            size = i2;
                        }
                        size = -1;
                    } else {
                        size = -1;
                    }
                    if (size < 0) {
                        throw new IllegalArgumentException(("A required auto migration spec (" + cls2.getCanonicalName() + ") is missing in the database configuration.").toString());
                    }
                    linkedHashMap.put(cls2, arrayList2.get(size));
                } else {
                    int size2 = arrayList2.size() - 1;
                    if (size2 >= 0) {
                        while (true) {
                            int i3 = size2 - 1;
                            if (!bitSet.get(size2)) {
                                throw new IllegalArgumentException("Unexpected auto migration specs found. Annotate AutoMigrationSpec implementation with @ProvidedAutoMigrationSpec annotation or remove this spec from the builder.");
                            }
                            if (i3 < 0) {
                                break;
                            }
                            size2 = i3;
                        }
                    }
                    for (androidx.room.migration.a aVar2 : p3.g(linkedHashMap)) {
                        int i4 = aVar2.a;
                        Q q = configuration.d;
                        LinkedHashMap linkedHashMap2 = (LinkedHashMap) q.a;
                        if (linkedHashMap2.containsKey(Integer.valueOf(i4))) {
                            Map mapC = (Map) linkedHashMap2.get(Integer.valueOf(i4));
                            if (mapC == null) {
                                mapC = kotlin.collections.V.c();
                            }
                            zContainsKey = mapC.containsKey(Integer.valueOf(aVar2.b));
                        } else {
                            zContainsKey = false;
                        }
                        if (!zContainsKey) {
                            q.z(aVar2);
                        }
                    }
                    p3.h().setWriteAheadLoggingEnabled(configuration.g == rVar4);
                    p3.g = configuration.e;
                    p3.b = configuration.h;
                    p3.c = new ExecutorC0060p(configuration.i);
                    p3.f = configuration.f;
                    Map mapJ = p3.j();
                    BitSet bitSet2 = new BitSet();
                    Iterator it5 = mapJ.entrySet().iterator();
                    while (true) {
                        boolean zHasNext2 = it5.hasNext();
                        ArrayList arrayList3 = configuration.m;
                        if (!zHasNext2) {
                            int size3 = arrayList3.size() - 1;
                            if (size3 >= 0) {
                                while (true) {
                                    int i5 = size3 - 1;
                                    if (!bitSet2.get(size3)) {
                                        throw new IllegalArgumentException("Unexpected type converter " + arrayList3.get(size3) + ". Annotate TypeConverter class with @ProvidedTypeConverter annotation or remove this converter from the builder.");
                                    }
                                    if (i5 < 0) {
                                        break;
                                    }
                                    size3 = i5;
                                }
                            }
                            Context applicationContext = p0.getApplicationContext();
                            Intrinsics.checkNotNullExpressionValue(applicationContext, "context.applicationContext");
                            androidx.work.impl.constraints.trackers.j p4 = new androidx.work.impl.constraints.trackers.j(applicationContext, workTaskExecutor);
                            C1433e p5 = new C1433e(p0.getApplicationContext(), p1, workTaskExecutor, p3);
                            s schedulersCreator = s.a;
                            Intrinsics.checkNotNullParameter(p0, "context");
                            Intrinsics.checkNotNullParameter(p1, "configuration");
                            Intrinsics.checkNotNullParameter(workTaskExecutor, "workTaskExecutor");
                            Intrinsics.checkNotNullParameter(p3, "workDatabase");
                            Intrinsics.checkNotNullParameter(p4, "trackers");
                            Intrinsics.checkNotNullParameter(p5, "processor");
                            Intrinsics.checkNotNullParameter(schedulersCreator, "schedulersCreator");
                            schedulersCreator.getClass();
                            androidx.work.impl.utils.taskexecutor.c p2 = workTaskExecutor;
                            Intrinsics.checkNotNullParameter(p0, "p0");
                            Intrinsics.checkNotNullParameter(p1, "p1");
                            Intrinsics.checkNotNullParameter(p2, "p2");
                            Intrinsics.checkNotNullParameter(p3, "p3");
                            Intrinsics.checkNotNullParameter(p4, "p4");
                            Intrinsics.checkNotNullParameter(p5, "p5");
                            int i6 = i.a;
                            androidx.work.impl.background.systemjob.d dVar2 = new androidx.work.impl.background.systemjob.d(p0, p3, p1);
                            androidx.work.impl.utils.h.a(p0, SystemJobService.class, true);
                            androidx.work.z.c().getClass();
                            Intrinsics.checkNotNullExpressionValue(dVar2, "createBestAvailableBackg…kDatabase, configuration)");
                            return new r(p0.getApplicationContext(), p1, workTaskExecutor, p3, kotlin.collections.B.j(dVar2, new androidx.work.impl.background.greedy.c(p0, p1, p4, p5, new androidx.work.impl.model.c(p5, p2), p2)), p5, p4);
                        }
                        Map.Entry entry = (Map.Entry) it5.next();
                        Class cls3 = (Class) entry.getKey();
                        for (Class cls4 : (List) entry.getValue()) {
                            int size4 = arrayList3.size() - 1;
                            if (size4 >= 0) {
                                while (true) {
                                    int i7 = size4 - 1;
                                    it2 = it5;
                                    if (cls4.isAssignableFrom(arrayList3.get(size4).getClass())) {
                                        bitSet2.set(size4);
                                        break;
                                    }
                                    if (i7 < 0) {
                                        break;
                                    }
                                    size4 = i7;
                                    it5 = it2;
                                }
                            } else {
                                it2 = it5;
                            }
                            size4 = -1;
                            if (!(size4 >= 0)) {
                                throw new IllegalArgumentException(("A required type converter (" + cls4 + ") for " + cls3.getCanonicalName() + " is missing in the database configuration.").toString());
                            }
                            p3.l.put(cls4, arrayList3.get(size4));
                            it5 = it2;
                        }
                    }
                }
            }
        } catch (ClassNotFoundException unused) {
            throw new RuntimeException("Cannot find implementation for " + WorkDatabase.class.getCanonicalName() + ". " + str + " does not exist");
        } catch (IllegalAccessException unused2) {
            throw new RuntimeException("Cannot access the constructor " + WorkDatabase.class.getCanonicalName());
        } catch (InstantiationException unused3) {
            throw new RuntimeException("Failed to create an instance of " + WorkDatabase.class.getCanonicalName());
        }
    }
}
