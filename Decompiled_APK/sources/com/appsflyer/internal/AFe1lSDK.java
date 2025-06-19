package com.appsflyer.internal;

import com.appsflyer.AFLogger;
import java.io.InterruptedIOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.NavigableSet;
import java.util.Set;
import java.util.Timer;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class AFe1lSDK {
    public final List<AFe1qSDK> AFAdRevenueData;
    final List<AFe1sSDK<?>> areAllFieldsValid;
    final Set<AFe1sSDK<?>> component1;
    final NavigableSet<AFe1sSDK<?>> component2;
    final Set<AFe1mSDK> component3;
    final NavigableSet<AFe1sSDK<?>> component4;
    final Timer getCurrencyIso4217Code;
    final ExecutorService getMediationNetwork;
    final Set<AFe1mSDK> getMonetizationNetwork;
    public Executor getRevenue;

    /* renamed from: com.appsflyer.internal.AFe1lSDK$4, reason: invalid class name */
    public class AnonymousClass4 implements Runnable {
        public AnonymousClass4() {
        }

        @Override // java.lang.Runnable
        public final void run() {
            synchronized (AFe1lSDK.this.component2) {
                try {
                    final AFe1sSDK<?> aFe1sSDKPollFirst = AFe1lSDK.this.component2.pollFirst();
                    if (aFe1sSDKPollFirst == null) {
                        return;
                    }
                    AFe1lSDK.this.component1.add(aFe1sSDKPollFirst);
                    long monetizationNetwork = aFe1sSDKPollFirst.getMonetizationNetwork();
                    AFe1pSDK aFe1pSDK = new AFe1pSDK(Thread.currentThread());
                    if (monetizationNetwork > 0) {
                        AFe1lSDK.this.getCurrencyIso4217Code.schedule(aFe1pSDK, monetizationNetwork);
                    }
                    final AFe1lSDK aFe1lSDK = AFe1lSDK.this;
                    aFe1lSDK.getRevenue.execute(new Runnable() { // from class: com.appsflyer.internal.AFe1lSDK.1
                        @Override // java.lang.Runnable
                        public final void run() {
                            Iterator<AFe1qSDK> it2 = AFe1lSDK.this.AFAdRevenueData.iterator();
                            while (it2.hasNext()) {
                                it2.next().getMonetizationNetwork(aFe1sSDKPollFirst);
                            }
                        }
                    });
                    if (!AFe1lSDK.this.component2.isEmpty()) {
                        AFe1lSDK aFe1lSDK2 = AFe1lSDK.this;
                        aFe1lSDK2.getMediationNetwork.submit(aFe1lSDK2.new AnonymousClass4());
                    }
                    try {
                        AFLogger.INSTANCE.d(AFg1cSDK.QUEUE, "starting task execution: ".concat(String.valueOf(aFe1sSDKPollFirst)));
                        final AFe1rSDK aFe1rSDKCall = aFe1sSDKPollFirst.call();
                        aFe1pSDK.cancel();
                        final AFe1lSDK aFe1lSDK3 = AFe1lSDK.this;
                        aFe1lSDK3.getRevenue.execute(new Runnable() { // from class: com.appsflyer.internal.AFe1lSDK.3
                            @Override // java.lang.Runnable
                            public final void run() {
                                AFLogger aFLogger = AFLogger.INSTANCE;
                                AFg1cSDK aFg1cSDK = AFg1cSDK.QUEUE;
                                StringBuilder sb = new StringBuilder("execution finished for ");
                                sb.append(aFe1sSDKPollFirst);
                                sb.append(", result: ");
                                sb.append(aFe1rSDKCall);
                                aFLogger.d(aFg1cSDK, sb.toString());
                                AFe1lSDK.this.component1.remove(aFe1sSDKPollFirst);
                                Iterator<AFe1qSDK> it2 = AFe1lSDK.this.AFAdRevenueData.iterator();
                                while (it2.hasNext()) {
                                    it2.next().getCurrencyIso4217Code(aFe1sSDKPollFirst, aFe1rSDKCall);
                                }
                                if (aFe1rSDKCall == AFe1rSDK.SUCCESS) {
                                    AFe1lSDK.this.getMonetizationNetwork.add(aFe1sSDKPollFirst.getMonetizationNetwork);
                                    AFe1lSDK.this.getCurrencyIso4217Code();
                                    return;
                                }
                                if (!aFe1sSDKPollFirst.getMediationNetwork()) {
                                    AFe1lSDK.this.getMonetizationNetwork.add(aFe1sSDKPollFirst.getMonetizationNetwork);
                                    AFe1lSDK.this.getCurrencyIso4217Code();
                                } else if (AFe1lSDK.getCurrencyIso4217Code(aFe1sSDKPollFirst)) {
                                    synchronized (AFe1lSDK.this.component2) {
                                        try {
                                            AFe1lSDK.this.areAllFieldsValid.add(aFe1sSDKPollFirst);
                                            for (AFe1qSDK aFe1qSDK : AFe1lSDK.this.AFAdRevenueData) {
                                            }
                                        } catch (Throwable th) {
                                            throw th;
                                        }
                                    }
                                }
                            }
                        });
                    } catch (InterruptedIOException | InterruptedException unused) {
                        AFLogger.INSTANCE.d(AFg1cSDK.QUEUE, "task was interrupted: ".concat(String.valueOf(aFe1sSDKPollFirst)));
                        final AFe1rSDK aFe1rSDK = AFe1rSDK.TIMEOUT;
                        aFe1sSDKPollFirst.getMediationNetwork = aFe1rSDK;
                        final AFe1lSDK aFe1lSDK4 = AFe1lSDK.this;
                        aFe1lSDK4.getRevenue.execute(new Runnable() { // from class: com.appsflyer.internal.AFe1lSDK.3
                            @Override // java.lang.Runnable
                            public final void run() {
                                AFLogger aFLogger = AFLogger.INSTANCE;
                                AFg1cSDK aFg1cSDK = AFg1cSDK.QUEUE;
                                StringBuilder sb = new StringBuilder("execution finished for ");
                                sb.append(aFe1sSDKPollFirst);
                                sb.append(", result: ");
                                sb.append(aFe1rSDK);
                                aFLogger.d(aFg1cSDK, sb.toString());
                                AFe1lSDK.this.component1.remove(aFe1sSDKPollFirst);
                                Iterator<AFe1qSDK> it2 = AFe1lSDK.this.AFAdRevenueData.iterator();
                                while (it2.hasNext()) {
                                    it2.next().getCurrencyIso4217Code(aFe1sSDKPollFirst, aFe1rSDK);
                                }
                                if (aFe1rSDK == AFe1rSDK.SUCCESS) {
                                    AFe1lSDK.this.getMonetizationNetwork.add(aFe1sSDKPollFirst.getMonetizationNetwork);
                                    AFe1lSDK.this.getCurrencyIso4217Code();
                                    return;
                                }
                                if (!aFe1sSDKPollFirst.getMediationNetwork()) {
                                    AFe1lSDK.this.getMonetizationNetwork.add(aFe1sSDKPollFirst.getMonetizationNetwork);
                                    AFe1lSDK.this.getCurrencyIso4217Code();
                                } else if (AFe1lSDK.getCurrencyIso4217Code(aFe1sSDKPollFirst)) {
                                    synchronized (AFe1lSDK.this.component2) {
                                        try {
                                            AFe1lSDK.this.areAllFieldsValid.add(aFe1sSDKPollFirst);
                                            for (AFe1qSDK aFe1qSDK : AFe1lSDK.this.AFAdRevenueData) {
                                            }
                                        } catch (Throwable th) {
                                            throw th;
                                        }
                                    }
                                }
                            }
                        });
                    } catch (Throwable unused2) {
                        aFe1pSDK.cancel();
                        final AFe1lSDK aFe1lSDK5 = AFe1lSDK.this;
                        final AFe1rSDK aFe1rSDK2 = AFe1rSDK.FAILURE;
                        aFe1lSDK5.getRevenue.execute(new Runnable() { // from class: com.appsflyer.internal.AFe1lSDK.3
                            @Override // java.lang.Runnable
                            public final void run() {
                                AFLogger aFLogger = AFLogger.INSTANCE;
                                AFg1cSDK aFg1cSDK = AFg1cSDK.QUEUE;
                                StringBuilder sb = new StringBuilder("execution finished for ");
                                sb.append(aFe1sSDKPollFirst);
                                sb.append(", result: ");
                                sb.append(aFe1rSDK2);
                                aFLogger.d(aFg1cSDK, sb.toString());
                                AFe1lSDK.this.component1.remove(aFe1sSDKPollFirst);
                                Iterator<AFe1qSDK> it2 = AFe1lSDK.this.AFAdRevenueData.iterator();
                                while (it2.hasNext()) {
                                    it2.next().getCurrencyIso4217Code(aFe1sSDKPollFirst, aFe1rSDK2);
                                }
                                if (aFe1rSDK2 == AFe1rSDK.SUCCESS) {
                                    AFe1lSDK.this.getMonetizationNetwork.add(aFe1sSDKPollFirst.getMonetizationNetwork);
                                    AFe1lSDK.this.getCurrencyIso4217Code();
                                    return;
                                }
                                if (!aFe1sSDKPollFirst.getMediationNetwork()) {
                                    AFe1lSDK.this.getMonetizationNetwork.add(aFe1sSDKPollFirst.getMonetizationNetwork);
                                    AFe1lSDK.this.getCurrencyIso4217Code();
                                } else if (AFe1lSDK.getCurrencyIso4217Code(aFe1sSDKPollFirst)) {
                                    synchronized (AFe1lSDK.this.component2) {
                                        try {
                                            AFe1lSDK.this.areAllFieldsValid.add(aFe1sSDKPollFirst);
                                            for (AFe1qSDK aFe1qSDK : AFe1lSDK.this.AFAdRevenueData) {
                                            }
                                        } catch (Throwable th) {
                                            throw th;
                                        }
                                    }
                                }
                            }
                        });
                    }
                } catch (Throwable th) {
                    throw th;
                }
            }
        }
    }

    /* renamed from: com.appsflyer.internal.AFe1lSDK$5, reason: invalid class name */
    public class AnonymousClass5 implements Runnable {
        private /* synthetic */ AFe1sSDK getMonetizationNetwork;

        public AnonymousClass5(AFe1sSDK aFe1sSDK) {
            this.getMonetizationNetwork = aFe1sSDK;
        }

        @Override // java.lang.Runnable
        public final void run() {
            boolean zAdd;
            synchronized (AFe1lSDK.this.component2) {
                try {
                    if (AFe1lSDK.this.component1.contains(this.getMonetizationNetwork)) {
                        AFLogger aFLogger = AFLogger.INSTANCE;
                        AFg1cSDK aFg1cSDK = AFg1cSDK.QUEUE;
                        StringBuilder sb = new StringBuilder("tried to add already running task: ");
                        sb.append(this.getMonetizationNetwork);
                        aFLogger.d(aFg1cSDK, sb.toString());
                        return;
                    }
                    if (!AFe1lSDK.this.component2.contains(this.getMonetizationNetwork) && !AFe1lSDK.this.component4.contains(this.getMonetizationNetwork)) {
                        AFe1lSDK aFe1lSDK = AFe1lSDK.this;
                        AFe1sSDK aFe1sSDK = this.getMonetizationNetwork;
                        for (AFe1mSDK aFe1mSDK : aFe1sSDK.AFAdRevenueData) {
                            if (aFe1lSDK.component3.contains(aFe1mSDK)) {
                                aFe1sSDK.getCurrencyIso4217Code.add(aFe1mSDK);
                            }
                        }
                        if (AFe1lSDK.this.AFAdRevenueData(this.getMonetizationNetwork)) {
                            zAdd = AFe1lSDK.this.component2.add(this.getMonetizationNetwork);
                        } else {
                            zAdd = AFe1lSDK.this.component4.add(this.getMonetizationNetwork);
                            if (zAdd) {
                                AFLogger aFLogger2 = AFLogger.INSTANCE;
                                AFg1cSDK aFg1cSDK2 = AFg1cSDK.QUEUE;
                                StringBuilder sb2 = new StringBuilder("new task was blocked: ");
                                sb2.append(this.getMonetizationNetwork);
                                aFLogger2.d(aFg1cSDK2, sb2.toString());
                                this.getMonetizationNetwork.AFAdRevenueData();
                            }
                        }
                        if (zAdd) {
                            AFe1lSDK aFe1lSDK2 = AFe1lSDK.this;
                            aFe1lSDK2.component2.addAll(aFe1lSDK2.areAllFieldsValid);
                            AFe1lSDK.this.areAllFieldsValid.clear();
                        } else {
                            AFLogger aFLogger3 = AFLogger.INSTANCE;
                            AFg1cSDK aFg1cSDK3 = AFg1cSDK.QUEUE;
                            StringBuilder sb3 = new StringBuilder("task not added, it's already in the queue: ");
                            sb3.append(this.getMonetizationNetwork);
                            aFLogger3.d(aFg1cSDK3, sb3.toString());
                        }
                        if (!zAdd) {
                            AFLogger aFLogger4 = AFLogger.INSTANCE;
                            AFg1cSDK aFg1cSDK4 = AFg1cSDK.QUEUE;
                            StringBuilder sb4 = new StringBuilder("QUEUE: tried to add already pending task: ");
                            sb4.append(this.getMonetizationNetwork);
                            aFLogger4.w(aFg1cSDK4, sb4.toString());
                            return;
                        }
                        AFe1lSDK.this.component3.add(this.getMonetizationNetwork.getMonetizationNetwork);
                        AFLogger aFLogger5 = AFLogger.INSTANCE;
                        AFg1cSDK aFg1cSDK5 = AFg1cSDK.QUEUE;
                        StringBuilder sb5 = new StringBuilder("new task added: ");
                        sb5.append(this.getMonetizationNetwork);
                        aFLogger5.d(aFg1cSDK5, sb5.toString());
                        for (AFe1qSDK aFe1qSDK : AFe1lSDK.this.AFAdRevenueData) {
                        }
                        AFe1lSDK aFe1lSDK3 = AFe1lSDK.this;
                        aFe1lSDK3.getMediationNetwork.submit(aFe1lSDK3.new AnonymousClass4());
                        AFe1lSDK aFe1lSDK4 = AFe1lSDK.this;
                        synchronized (aFe1lSDK4.component2) {
                            try {
                                for (int size = (aFe1lSDK4.component2.size() + aFe1lSDK4.component4.size()) - 40; size > 0; size--) {
                                    boolean zIsEmpty = aFe1lSDK4.component4.isEmpty();
                                    boolean zIsEmpty2 = aFe1lSDK4.component2.isEmpty();
                                    if (zIsEmpty2 || zIsEmpty) {
                                        if (!zIsEmpty2) {
                                            aFe1lSDK4.getMediationNetwork(aFe1lSDK4.component2);
                                        } else if (!zIsEmpty) {
                                            aFe1lSDK4.getMediationNetwork(aFe1lSDK4.component4);
                                        }
                                    } else if (aFe1lSDK4.component2.first().compareTo(aFe1lSDK4.component4.first()) > 0) {
                                        aFe1lSDK4.getMediationNetwork(aFe1lSDK4.component2);
                                    } else {
                                        aFe1lSDK4.getMediationNetwork(aFe1lSDK4.component4);
                                    }
                                }
                            } catch (Throwable th) {
                                throw th;
                            }
                        }
                        return;
                    }
                    AFLogger aFLogger6 = AFLogger.INSTANCE;
                    AFg1cSDK aFg1cSDK6 = AFg1cSDK.QUEUE;
                    StringBuilder sb6 = new StringBuilder("tried to add already scheduled task: ");
                    sb6.append(this.getMonetizationNetwork);
                    aFLogger6.d(aFg1cSDK6, sb6.toString());
                } catch (Throwable th2) {
                    throw th2;
                }
            }
        }
    }

    public AFe1lSDK(ExecutorService executorService) {
        ExecutorService executorServiceNewSingleThreadExecutor = Executors.newSingleThreadExecutor();
        Intrinsics.checkNotNullExpressionValue(executorServiceNewSingleThreadExecutor, "");
        this.getRevenue = executorServiceNewSingleThreadExecutor;
        this.getCurrencyIso4217Code = new Timer(true);
        this.AFAdRevenueData = new CopyOnWriteArrayList();
        this.getMonetizationNetwork = new CopyOnWriteArraySet();
        this.component3 = Collections.newSetFromMap(new ConcurrentHashMap());
        this.component2 = new ConcurrentSkipListSet();
        this.component4 = new ConcurrentSkipListSet();
        this.areAllFieldsValid = new ArrayList();
        this.component1 = Collections.newSetFromMap(new ConcurrentHashMap());
        this.getMediationNetwork = executorService;
    }

    public final boolean AFAdRevenueData(AFe1sSDK<?> aFe1sSDK) {
        return this.getMonetizationNetwork.containsAll(aFe1sSDK.getCurrencyIso4217Code);
    }

    public final void getCurrencyIso4217Code() {
        synchronized (this.component2) {
            try {
                Iterator<AFe1sSDK<?>> it2 = this.component4.iterator();
                boolean z = false;
                while (it2.hasNext()) {
                    AFe1sSDK<?> next = it2.next();
                    if (AFAdRevenueData(next)) {
                        it2.remove();
                        this.component2.add(next);
                        z = true;
                    }
                }
                if (z) {
                    this.getMediationNetwork.submit(new AnonymousClass4());
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void getMediationNetwork(NavigableSet<AFe1sSDK<?>> navigableSet) {
        AFe1sSDK<?> aFe1sSDKPollFirst = navigableSet.pollFirst();
        this.getMonetizationNetwork.add(aFe1sSDKPollFirst.getMonetizationNetwork);
        Iterator<AFe1qSDK> it2 = this.AFAdRevenueData.iterator();
        while (it2.hasNext()) {
            it2.next().getMediationNetwork(aFe1sSDKPollFirst);
        }
    }

    public static boolean getCurrencyIso4217Code(AFe1sSDK<?> aFe1sSDK) {
        return ((aFe1sSDK instanceof AFf1vSDK) && aFe1sSDK.getMonetizationNetwork == AFe1mSDK.ARS_VALIDATE) ? false : true;
    }
}
