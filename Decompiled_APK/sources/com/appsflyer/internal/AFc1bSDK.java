package com.appsflyer.internal;

import android.content.Context;
import com.appsflyer.AFLogger;
import com.appsflyer.internal.AFc1cSDK;
import java.io.File;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import kotlin.Unit;
import kotlin.collections.C;
import kotlin.collections.C4933y;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.collections.Z;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class AFc1bSDK implements AFc1aSDK {

    @NotNull
    private final AFc1iSDK AFAdRevenueData;

    public AFc1bSDK(@NotNull AFc1iSDK aFc1iSDK) {
        Intrinsics.checkNotNullParameter(aFc1iSDK, "");
        this.AFAdRevenueData = aFc1iSDK;
    }

    private final File getRevenue() {
        Context context = this.AFAdRevenueData.getMonetizationNetwork;
        if (context == null) {
            return null;
        }
        File file = new File(context.getFilesDir(), "AFExceptionsCache");
        if (!file.exists()) {
            file.mkdirs();
        }
        return file;
    }

    @Override // com.appsflyer.internal.AFc1aSDK
    public final String AFAdRevenueData(@NotNull Throwable th, @NotNull String str) {
        String str2;
        File file;
        Intrinsics.checkNotNullParameter(th, "");
        Intrinsics.checkNotNullParameter(str, "");
        synchronized (this) {
            File revenue = getRevenue();
            str2 = null;
            if (revenue != null) {
                file = new File(revenue, "6.17.0");
                if (!file.exists()) {
                    file.mkdirs();
                }
            } else {
                file = null;
            }
            if (file != null) {
                try {
                    AFc1cSDK currencyIso4217Code = AFd1qSDK.getCurrencyIso4217Code(th, str);
                    String str3 = currencyIso4217Code.getMonetizationNetwork;
                    File file2 = new File(file, str3);
                    if (file2.exists()) {
                        AFc1cSDK.AFa1ySDK aFa1ySDK = AFc1cSDK.AFa1ySDK;
                        AFc1cSDK revenue2 = AFc1cSDK.AFa1ySDK.getRevenue(kotlin.io.i.a(file2));
                        if (revenue2 != null) {
                            revenue2.getMediationNetwork++;
                            currencyIso4217Code = revenue2;
                        }
                    }
                    kotlin.io.i.b(file2, currencyIso4217Code.AFAdRevenueData());
                    str2 = str3;
                } catch (Exception e) {
                    AFg1gSDK.v$default(AFLogger.INSTANCE, AFg1cSDK.EXCEPTION_MANAGER, "Could not cache exception\n " + e.getMessage(), false, 4, null);
                }
            }
        }
        return str2;
    }

    @Override // com.appsflyer.internal.AFc1aSDK
    public final int getCurrencyIso4217Code() {
        Iterator<T> it2 = getMediationNetwork().iterator();
        int i = 0;
        while (it2.hasNext()) {
            i += ((AFc1cSDK) it2.next()).getMediationNetwork;
        }
        return i;
    }

    @Override // com.appsflyer.internal.AFc1aSDK
    @NotNull
    public final List<AFc1cSDK> getMediationNetwork() {
        List<AFc1cSDK> listR;
        File[] fileArrListFiles;
        ArrayList arrayList;
        File[] fileArrListFiles2;
        synchronized (this) {
            try {
                File revenue = getRevenue();
                listR = null;
                if (revenue != null && (fileArrListFiles = revenue.listFiles()) != null) {
                    ArrayList arrayList2 = new ArrayList();
                    for (File file : fileArrListFiles) {
                        try {
                            fileArrListFiles2 = file.listFiles();
                        } catch (Throwable th) {
                            AFg1gSDK.v$default(AFLogger.INSTANCE, AFg1cSDK.EXCEPTION_MANAGER, "Could not get stored exceptions\n " + th.getMessage(), false, 4, null);
                        }
                        if (fileArrListFiles2 != null) {
                            Intrinsics.checkNotNullExpressionValue(fileArrListFiles2, "");
                            arrayList = new ArrayList();
                            for (File file2 : fileArrListFiles2) {
                                AFc1cSDK.AFa1ySDK aFa1ySDK = AFc1cSDK.AFa1ySDK;
                                Intrinsics.checkNotNullExpressionValue(file2, "");
                                AFc1cSDK revenue2 = AFc1cSDK.AFa1ySDK.getRevenue(kotlin.io.i.a(file2));
                                if (revenue2 != null) {
                                    arrayList.add(revenue2);
                                }
                            }
                        } else {
                            arrayList = null;
                        }
                        if (arrayList != null) {
                            arrayList2.add(arrayList);
                        }
                    }
                    listR = C.r(arrayList2);
                }
                if (listR == null) {
                    listR = K.a;
                }
            } catch (Throwable th2) {
                throw th2;
            }
        }
        return listR;
    }

    @Override // com.appsflyer.internal.AFc1aSDK
    public final boolean getMonetizationNetwork() {
        return getRevenue(new String[0]);
    }

    @Override // com.appsflyer.internal.AFc1aSDK
    public final boolean getRevenue(@NotNull String... strArr) {
        boolean zE;
        Intrinsics.checkNotNullParameter(strArr, "");
        synchronized (this) {
            try {
                File revenue = getRevenue();
                zE = true;
                if (revenue != null) {
                    if (strArr.length == 0) {
                        AFg1gSDK.v$default(AFLogger.INSTANCE, AFg1cSDK.EXCEPTION_MANAGER, "delete all exceptions", false, 4, null);
                        zE = kotlin.io.k.e(revenue);
                    } else {
                        AFg1gSDK.v$default(AFLogger.INSTANCE, AFg1cSDK.EXCEPTION_MANAGER, "delete all exceptions except for: " + C4933y.H(strArr, ", ", null, 62), false, 4, null);
                        File[] fileArrListFiles = revenue.listFiles();
                        if (fileArrListFiles != null) {
                            Intrinsics.checkNotNullExpressionValue(fileArrListFiles, "");
                            ArrayList arrayList = new ArrayList();
                            for (File file : fileArrListFiles) {
                                if (!C4933y.u(file.getName(), strArr)) {
                                    arrayList.add(file);
                                }
                            }
                            ArrayList arrayList2 = new ArrayList(C.q(arrayList, 10));
                            Iterator it2 = arrayList.iterator();
                            while (it2.hasNext()) {
                                File file2 = (File) it2.next();
                                Intrinsics.checkNotNullExpressionValue(file2, "");
                                arrayList2.add(Boolean.valueOf(kotlin.io.k.e(file2)));
                            }
                            Set setA0 = CollectionsKt.A0(arrayList2);
                            if (setA0.isEmpty()) {
                                setA0 = Z.b(Boolean.TRUE);
                            }
                            Set set = setA0;
                            if (set.size() != 1 || !((Boolean) CollectionsKt.K(set)).booleanValue()) {
                                zE = false;
                            }
                        }
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return zE;
    }

    @Override // com.appsflyer.internal.AFc1aSDK
    public final void AFAdRevenueData(int i, int i2) {
        File[] fileArrListFiles;
        synchronized (this) {
            try {
                File revenue = getRevenue();
                if (revenue != null && (fileArrListFiles = revenue.listFiles()) != null) {
                    Intrinsics.checkNotNullExpressionValue(fileArrListFiles, "");
                    ArrayList<File> arrayList = new ArrayList();
                    for (File file : fileArrListFiles) {
                        String name = file.getName();
                        Intrinsics.checkNotNullExpressionValue(name, "");
                        int monetizationNetwork = AFj1aSDK.getMonetizationNetwork(name);
                        if (i > monetizationNetwork || monetizationNetwork > i2) {
                            arrayList.add(file);
                        }
                    }
                    ArrayList arrayList2 = new ArrayList(C.q(arrayList, 10));
                    for (File file2 : arrayList) {
                        Intrinsics.checkNotNullExpressionValue(file2, "");
                        arrayList2.add(Boolean.valueOf(kotlin.io.k.e(file2)));
                    }
                }
                Unit unit = Unit.a;
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
