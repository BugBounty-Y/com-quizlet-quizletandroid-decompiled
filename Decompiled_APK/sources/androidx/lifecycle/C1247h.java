package androidx.lifecycle;

import android.app.ActivityManager;
import android.app.job.JobInfo;
import android.app.job.JobScheduler;
import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Canvas;
import android.graphics.ColorSpace;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.drawable.BitmapDrawable;
import android.os.Build;
import androidx.navigation.C1291m;
import androidx.navigation.C1294p;
import androidx.work.impl.WorkDatabase;
import androidx.work.impl.WorkDatabase_Impl;
import com.braze.BrazeUser;
import com.braze.enums.DeviceKey;
import com.braze.enums.Gender;
import com.braze.managers.BrazeGeofenceManager;
import com.braze.managers.C1489b;
import com.braze.managers.C1495h;
import com.braze.models.BrazeGeofence;
import com.braze.models.FeatureFlag;
import com.comscore.streaming.EventType;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_camera.D2;
import com.google.android.gms.internal.mlkit_vision_camera.s3;
import com.google.android.gms.tasks.Task;
import com.skydoves.balloon.internals.DefinitionKt;
import io.ktor.client.plugins.C4864k;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import okio.AbstractC5085b;

/* renamed from: androidx.lifecycle.h, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class C1247h implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ C1247h(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() throws Exception {
        boolean z;
        int largeMemoryClass;
        boolean z2;
        double d;
        coil3.decode.l lVar;
        Bitmap bitmapCreateBitmap;
        int i;
        int iMin;
        double dMax;
        int i2;
        int i3 = 3;
        Object obj = this.b;
        switch (this.a) {
            case 0:
                ((C1249j) obj).n = null;
                return Unit.a;
            case 1:
                return p0.i((C0) obj);
            case 2:
                androidx.navigation.internal.c cVar = ((C1291m) obj).h;
                if (!cVar.i) {
                    throw new IllegalStateException("You cannot access the NavBackStackEntry's SavedStateHandle until it is added to the NavController's back stack (i.e., the Lifecycle of the NavBackStackEntry reaches the CREATED state).");
                }
                if (cVar.j.d != B.a) {
                    return ((androidx.navigation.internal.b) com.google.mlkit.common.sdkinternal.model.a.p(cVar.a, (y0) cVar.m.getValue(), 4).b(kotlin.jvm.internal.K.a(androidx.navigation.internal.b.class))).b;
                }
                throw new IllegalStateException("You cannot access the NavBackStackEntry's SavedStateHandle after the NavBackStackEntry is destroyed.");
            case 3:
                ((C1294p) obj).invoke();
                return Unit.a;
            case 4:
                androidx.savedstate.f fVar = (androidx.savedstate.f) obj;
                fVar.getLifecycle().a(new androidx.savedstate.a(fVar));
                return Unit.a;
            case 5:
                androidx.work.impl.n nVar = (androidx.work.impl.n) obj;
                nVar.getClass();
                String str = androidx.work.impl.utils.b.a;
                HashSet hashSet = new HashSet();
                hashSet.addAll(nVar.e);
                HashSet hashSetD = androidx.work.impl.n.d(nVar);
                Iterator it2 = hashSet.iterator();
                while (true) {
                    if (!it2.hasNext()) {
                        hashSet.removeAll(nVar.e);
                        z = false;
                    } else if (hashSetD.contains((String) it2.next())) {
                        z = true;
                    }
                }
                if (z) {
                    throw new IllegalStateException("WorkContinuation has cycles (" + nVar + ")");
                }
                androidx.work.impl.r rVar = nVar.a;
                WorkDatabase workDatabase = rVar.c;
                workDatabase.c();
                try {
                    D2.a(workDatabase, rVar.b, nVar);
                    boolean zA = androidx.work.impl.utils.b.a(nVar);
                    workDatabase.p();
                    if (zA) {
                        androidx.work.impl.i.b(rVar.b, rVar.c, rVar.e);
                    }
                    return Unit.a;
                } finally {
                    workDatabase.k();
                }
            case 6:
                androidx.work.impl.r rVar2 = (androidx.work.impl.r) obj;
                rVar2.getClass();
                int i4 = Build.VERSION.SDK_INT;
                String str2 = androidx.work.impl.background.systemjob.d.f;
                Context context = rVar2.a;
                if (i4 >= 34) {
                    androidx.work.impl.background.systemjob.a.b(context).cancelAll();
                }
                JobScheduler jobScheduler = (JobScheduler) context.getSystemService("jobscheduler");
                ArrayList arrayListD = androidx.work.impl.background.systemjob.d.d(context, jobScheduler);
                if (arrayListD != null && !arrayListD.isEmpty()) {
                    Iterator it3 = arrayListD.iterator();
                    while (it3.hasNext()) {
                        androidx.work.impl.background.systemjob.d.b(jobScheduler, ((JobInfo) it3.next()).getId());
                    }
                }
                WorkDatabase workDatabase2 = rVar2.c;
                androidx.work.impl.model.t tVarU = workDatabase2.u();
                WorkDatabase_Impl workDatabase_Impl = (WorkDatabase_Impl) tVarU.a;
                workDatabase_Impl.b();
                androidx.work.impl.model.h hVar = (androidx.work.impl.model.h) tVarU.m;
                androidx.sqlite.db.framework.i iVarA = hVar.a();
                try {
                    workDatabase_Impl.c();
                    try {
                        iVarA.a();
                        workDatabase_Impl.p();
                        hVar.n(iVarA);
                        androidx.work.impl.i.b(rVar2.b, workDatabase2, rVar2.e);
                        return Unit.a;
                    } finally {
                        workDatabase_Impl.k();
                    }
                } catch (Throwable th) {
                    hVar.n(iVarA);
                    throw th;
                }
            case 7:
                return kotlin.collections.A.b((Pair) obj);
            case 8:
                Context context2 = ((coil3.l) obj).a;
                double d2 = 0.2d;
                try {
                    Object systemService = context2.getSystemService((Class<Object>) ActivityManager.class);
                    Intrinsics.d(systemService);
                    if (((ActivityManager) systemService).isLowRamDevice()) {
                        d2 = 0.15d;
                    }
                } catch (Exception unused) {
                }
                if (0.0d > d2 || d2 > 1.0d) {
                    throw new IllegalArgumentException("percent must be in the range [0.0, 1.0].");
                }
                com.android.billingclient.api.s sVar = new com.android.billingclient.api.s(6, (byte) 0);
                try {
                    Object systemService2 = context2.getSystemService((Class<Object>) ActivityManager.class);
                    Intrinsics.d(systemService2);
                    ActivityManager activityManager = (ActivityManager) systemService2;
                    largeMemoryClass = (context2.getApplicationInfo().flags & 1048576) != 0 ? activityManager.getLargeMemoryClass() : activityManager.getMemoryClass();
                } catch (Exception unused2) {
                    largeMemoryClass = 256;
                }
                long j = (long) (d2 * largeMemoryClass * 1048576);
                return new coil3.memory.c(j > 0 ? new androidx.work.impl.model.v(j, sVar) : new com.google.android.gms.auth.api.signin.internal.h(sVar, 17), sVar);
            case 9:
                BitmapFactory.Options options = new BitmapFactory.Options();
                coil3.decode.e eVar = (coil3.decode.e) obj;
                coil3.decode.b bVar = new coil3.decode.b(eVar.a.f0());
                okio.A aC = AbstractC5085b.c(bVar);
                options.inJustDecodeBounds = true;
                BitmapFactory.decodeStream(new C4864k(aC.peek(), i3), null, options);
                Exception exc = (Exception) bVar.c;
                if (exc != null) {
                    throw exc;
                }
                options.inJustDecodeBounds = false;
                Paint paint = coil3.decode.o.a;
                String str3 = options.outMimeType;
                switch (eVar.d.a) {
                    case 0:
                        if (str3 == null || (!str3.equals("image/jpeg") && !str3.equals("image/webp") && !str3.equals("image/heic") && !str3.equals("image/heif"))) {
                            z2 = false;
                            break;
                        }
                        break;
                    default:
                        z2 = true;
                        break;
                }
                if (z2) {
                    d = 1.0d;
                    androidx.exifinterface.media.h hVar2 = new androidx.exifinterface.media.h(new coil3.decode.m(new C4864k(aC.peek(), i3)));
                    int iC = hVar2.c(1, "Orientation");
                    boolean z3 = iC == 2 || iC == 7 || iC == 4 || iC == 5;
                    switch (hVar2.c(1, "Orientation")) {
                        case 3:
                        case 4:
                            i2 = SubsamplingScaleImageView.ORIENTATION_180;
                            break;
                        case 5:
                        case 8:
                            i2 = 270;
                            break;
                        case 6:
                        case 7:
                            i2 = 90;
                            break;
                        default:
                            i2 = 0;
                            break;
                    }
                    lVar = new coil3.decode.l(z3, i2);
                } else {
                    d = 1.0d;
                    lVar = coil3.decode.l.c;
                }
                Exception exc2 = (Exception) bVar.c;
                if (exc2 != null) {
                    throw exc2;
                }
                options.inMutable = false;
                androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList.e eVar2 = coil3.request.i.c;
                coil3.request.m mVar = eVar.b;
                if (((ColorSpace) coil3.n.e(mVar, eVar2)) != null) {
                    options.inPreferredColorSpace = (ColorSpace) coil3.n.e(mVar, eVar2);
                }
                options.inPremultiplied = ((Boolean) coil3.n.e(mVar, coil3.request.i.d)).booleanValue();
                Bitmap.Config config = (Bitmap.Config) coil3.n.e(mVar, coil3.request.i.b);
                int i5 = lVar.b;
                boolean z4 = lVar.a;
                if ((z4 || i5 > 0) && (config == null || config == Bitmap.Config.HARDWARE)) {
                    config = Bitmap.Config.ARGB_8888;
                }
                if (((Boolean) coil3.n.e(mVar, coil3.request.i.g)).booleanValue() && config == Bitmap.Config.ARGB_8888 && Intrinsics.b(options.outMimeType, "image/jpeg")) {
                    config = Bitmap.Config.RGB_565;
                }
                Bitmap.Config config2 = options.outConfig;
                Bitmap.Config config3 = Bitmap.Config.RGBA_F16;
                if (config2 == config3 && config != Bitmap.Config.HARDWARE) {
                    config = config3;
                }
                options.inPreferredConfig = config;
                int i6 = options.outWidth;
                if (i6 <= 0 || (i = options.outHeight) <= 0) {
                    options.inSampleSize = 1;
                    options.inScaled = false;
                } else {
                    int i7 = (i5 == 90 || i5 == 270) ? i : i6;
                    if (i5 != 90 && i5 != 270) {
                        i6 = i;
                    }
                    coil3.size.h hVar3 = (coil3.size.h) coil3.n.e(mVar, coil3.request.h.b);
                    coil3.size.h hVar4 = mVar.b;
                    coil3.size.g gVar = mVar.c;
                    long jA = s3.a(i7, i6, hVar4, gVar, hVar3);
                    int i8 = (int) (jA >> 32);
                    int i9 = (int) (jA & 4294967295L);
                    int iHighestOneBit = Integer.highestOneBit(i7 / i8);
                    int iHighestOneBit2 = Integer.highestOneBit(i6 / i9);
                    int iOrdinal = gVar.ordinal();
                    if (iOrdinal == 0) {
                        iMin = Math.min(iHighestOneBit, iHighestOneBit2);
                    } else {
                        if (iOrdinal != 1) {
                            throw new NoWhenBranchMatchedException();
                        }
                        iMin = Math.max(iHighestOneBit, iHighestOneBit2);
                    }
                    if (iMin < 1) {
                        iMin = 1;
                    }
                    options.inSampleSize = iMin;
                    double d3 = i7;
                    double d4 = iMin;
                    double d5 = i6 / d4;
                    double d6 = i8 / (d3 / d4);
                    double d7 = i9 / d5;
                    int iOrdinal2 = gVar.ordinal();
                    if (iOrdinal2 == 0) {
                        dMax = Math.max(d6, d7);
                    } else {
                        if (iOrdinal2 != 1) {
                            throw new NoWhenBranchMatchedException();
                        }
                        dMax = Math.min(d6, d7);
                    }
                    if (mVar.d == coil3.size.d.b && dMax > d) {
                        dMax = d;
                    }
                    boolean z5 = dMax == d;
                    options.inScaled = !z5;
                    if (!z5) {
                        if (dMax > d) {
                            options.inDensity = kotlin.math.c.a(SubsamplingScaleImageView.TILE_SIZE_AUTO / dMax);
                            options.inTargetDensity = SubsamplingScaleImageView.TILE_SIZE_AUTO;
                        } else {
                            options.inDensity = SubsamplingScaleImageView.TILE_SIZE_AUTO;
                            options.inTargetDensity = kotlin.math.c.a(SubsamplingScaleImageView.TILE_SIZE_AUTO * dMax);
                        }
                    }
                }
                try {
                    Bitmap bitmapDecodeStream = BitmapFactory.decodeStream(new C4864k(aC, 3), null, options);
                    aC.close();
                    Exception exc3 = (Exception) bVar.c;
                    if (exc3 != null) {
                        throw exc3;
                    }
                    if (bitmapDecodeStream == null) {
                        throw new IllegalStateException("BitmapFactory returned a null bitmap. Often this means BitmapFactory could not decode the image data read from the image source (e.g. network, disk, or memory) as it's not encoded as a valid image format.");
                    }
                    Context context3 = mVar.a;
                    bitmapDecodeStream.setDensity(context3.getResources().getDisplayMetrics().densityDpi);
                    if (z4 || i5 > 0) {
                        Matrix matrix = new Matrix();
                        float width = bitmapDecodeStream.getWidth() / 2.0f;
                        float height = bitmapDecodeStream.getHeight() / 2.0f;
                        if (z4) {
                            matrix.postScale(-1.0f, 1.0f, width, height);
                        }
                        if (i5 > 0) {
                            matrix.postRotate(i5, width, height);
                        }
                        RectF rectF = new RectF(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, bitmapDecodeStream.getWidth(), bitmapDecodeStream.getHeight());
                        matrix.mapRect(rectF);
                        float f = rectF.left;
                        if (f != DefinitionKt.NO_Float_VALUE || rectF.top != DefinitionKt.NO_Float_VALUE) {
                            matrix.postTranslate(-f, -rectF.top);
                        }
                        if (i5 == 90 || i5 == 270) {
                            int height2 = bitmapDecodeStream.getHeight();
                            int width2 = bitmapDecodeStream.getWidth();
                            Bitmap.Config config4 = bitmapDecodeStream.getConfig();
                            if (config4 == null) {
                                config4 = Bitmap.Config.ARGB_8888;
                            }
                            bitmapCreateBitmap = Bitmap.createBitmap(height2, width2, config4);
                        } else {
                            int width3 = bitmapDecodeStream.getWidth();
                            int height3 = bitmapDecodeStream.getHeight();
                            Bitmap.Config config5 = bitmapDecodeStream.getConfig();
                            if (config5 == null) {
                                config5 = Bitmap.Config.ARGB_8888;
                            }
                            bitmapCreateBitmap = Bitmap.createBitmap(width3, height3, config5);
                        }
                        new Canvas(bitmapCreateBitmap).drawBitmap(bitmapDecodeStream, matrix, coil3.decode.o.a);
                        bitmapDecodeStream.recycle();
                        bitmapDecodeStream = bitmapCreateBitmap;
                    }
                    return new coil3.decode.i(coil3.n.c(new BitmapDrawable(context3.getResources(), bitmapDecodeStream)), options.inSampleSize > 1 || options.inScaled);
                } finally {
                }
            case 10:
                return (coil3.disk.i) ((coil3.u) obj).a.d.getValue();
            case 11:
                return BrazeUser.setGender$lambda$17((Gender) obj);
            case 12:
                return com.braze.dispatch.g.a((com.braze.storage.z) obj);
            case 13:
                return com.braze.events.a.a((com.braze.events.e) obj);
            case 14:
                return BrazeGeofenceManager.registerGeofences$lambda$37$lambda$35((BrazeGeofence) obj);
            case 15:
                return com.braze.managers.a0.b((FeatureFlag) obj);
            case 16:
                return com.braze.managers.a0.a((com.braze.managers.a0) obj);
            case 17:
                return C1489b.a((C1489b) obj);
            case 18:
                return com.braze.managers.b0.a((Task) obj);
            case 19:
                return C1495h.a((C1495h) obj);
            case 20:
                return com.braze.managers.i0.a((com.braze.models.push.a) obj);
            case 21:
                return com.braze.managers.r.a((com.braze.managers.r) obj);
            case EventType.WINDOW_STATE /* 22 */:
                return com.braze.managers.s0.a((com.braze.managers.o0) obj);
            case EventType.AUDIO /* 23 */:
                return com.braze.managers.s0.a((com.braze.events.internal.t) obj);
            case EventType.VIDEO /* 24 */:
                return com.braze.managers.y.b((com.braze.models.dust.e) obj);
            case EventType.SUBS /* 25 */:
                return com.braze.managers.y.a((com.braze.models.dust.d) obj);
            case EventType.CDN /* 26 */:
                return com.braze.managers.z.a((Set) obj);
            case 27:
                return com.braze.models.outgoing.event.a.b((com.braze.models.o) obj);
            case 28:
                return com.braze.models.outgoing.g.a((DeviceKey) obj);
            default:
                return com.braze.requests.framework.b.a((com.braze.requests.framework.h) obj);
        }
    }
}
