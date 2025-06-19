package com.comscore.android.id;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Looper;
import android.os.Parcel;
import android.os.RemoteException;
import android.provider.Settings;
import com.amazon.device.ads.DtbDeviceDataRetriever;
import com.google.android.gms.internal.appset.g;
import com.google.android.gms.internal.mlkit_vision_common.S3;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/* loaded from: classes.dex */
public class IdHelperAndroid {
    public static final String NO_ID_AVAILABLE = "none";
    public static final String[] INVALID_ID_VALUES = {"0123456789ABCDEF", "0123456789abcdef", "9774d56d682e549c", "9774D56D682E549C", DtbDeviceDataRetriever.ORIENTATION_UNKNOWN, "UNKNOWN", "android_id", "ANDROID_ID"};
    public static final String[] INVALID_AD_ID_VALUES = {"00000000-0000-0000-0000-000000000000"};
    private static boolean c = false;
    private static final String a = "com.google.android.gms";
    private static final String b = "com.google.android.gms.ads.identifier.service.START";

    public static final class a implements ServiceConnection {
        boolean a;
        private final LinkedBlockingQueue<IBinder> b;

        public /* synthetic */ a(int i) {
            this();
        }

        public IBinder a() throws InterruptedException {
            if (this.a) {
                throw new IllegalStateException();
            }
            this.a = true;
            return this.b.take();
        }

        @Override // android.content.ServiceConnection
        public void onServiceConnected(ComponentName componentName, IBinder iBinder) throws InterruptedException {
            try {
                this.b.put(iBinder);
            } catch (InterruptedException unused) {
            }
        }

        @Override // android.content.ServiceConnection
        public void onServiceDisconnected(ComponentName componentName) {
        }

        private a() {
            this.a = false;
            this.b = new LinkedBlockingQueue<>(1);
        }
    }

    public static final class b implements IInterface {
        private IBinder a;

        public b(IBinder iBinder) {
            this.a = iBinder;
        }

        public boolean a(boolean z) throws RemoteException {
            Parcel parcelObtain = Parcel.obtain();
            Parcel parcelObtain2 = Parcel.obtain();
            try {
                parcelObtain.writeInterfaceToken("com.google.android.gms.ads.identifier.internal.IAdvertisingIdService");
                parcelObtain.writeInt(z ? 1 : 0);
                this.a.transact(2, parcelObtain, parcelObtain2, 0);
                parcelObtain2.readException();
                return parcelObtain2.readInt() != 0;
            } finally {
                parcelObtain2.recycle();
                parcelObtain.recycle();
            }
        }

        @Override // android.os.IInterface
        public IBinder asBinder() {
            return this.a;
        }

        public String getId() throws RemoteException {
            Parcel parcelObtain = Parcel.obtain();
            Parcel parcelObtain2 = Parcel.obtain();
            try {
                parcelObtain.writeInterfaceToken("com.google.android.gms.ads.identifier.internal.IAdvertisingIdService");
                this.a.transact(1, parcelObtain, parcelObtain2, 0);
                parcelObtain2.readException();
                return parcelObtain2.readString();
            } finally {
                parcelObtain2.recycle();
                parcelObtain.recycle();
            }
        }
    }

    private static Boolean a(Context context, boolean z) {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            throw new IllegalStateException("Cannot be called from the main thread");
        }
        if (!z && c) {
            return Boolean.FALSE;
        }
        try {
            boolean z2 = Settings.Secure.getInt(context.getContentResolver(), "limit_ad_tracking") == 0;
            if (!z && !z2) {
                c = true;
            }
            return Boolean.valueOf(z2);
        } catch (Exception unused) {
            return null;
        }
    }

    private static boolean b(Context context) {
        if (Build.MODEL.matches("AFTN")) {
            return true;
        }
        return context.getPackageManager().hasSystemFeature("amazon.hardware.fire_tv");
    }

    public static String getAmazonAdvertisingId(Context context, boolean z) {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            throw new IllegalStateException("Cannot be called from the main thread");
        }
        Boolean boolA = a(context, z);
        if (boolA == null) {
            return null;
        }
        return boolA.booleanValue() ? a(context) : NO_ID_AVAILABLE;
    }

    public static com.google.android.gms.appset.b getAppSetID(Context context) {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            throw new IllegalStateException("Cannot be called from the main thread");
        }
        try {
            return (com.google.android.gms.appset.b) S3.f(new g(context).b(), 5L, TimeUnit.SECONDS);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static CrossPublisherId getCrossPublisherDeviceId(Context context) {
        return getCrossPublisherDeviceId(context, false);
    }

    public static DeviceId getDeviceId(Context context) {
        com.google.android.gms.appset.b appSetID = getAppSetID(context);
        if (appSetID != null) {
            int i = appSetID.b;
            if (i == 1) {
                return new DeviceId("AppSetIdScopeApp", appSetID.a, 7, 2, 4);
            }
            if (i == 2) {
                return new DeviceId("AppSetIdScopeDeveloper", appSetID.a, 6, 2, 3);
            }
        }
        return a();
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x0022  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.comscore.android.id.DeviceId getGooglePlayAdvertisingDeviceId(android.content.Context r7, boolean r8) {
        /*
            android.os.Looper r0 = android.os.Looper.myLooper()
            android.os.Looper r1 = android.os.Looper.getMainLooper()
            if (r0 == r1) goto L32
            boolean r0 = isGooglePlayServicesAvailable(r7)
            if (r0 == 0) goto L30
            boolean r8 = isAdvertisingIdEnabled(r7, r8)
            java.lang.String r0 = "none"
            if (r8 == 0) goto L22
            java.lang.String r7 = getGooglePlayAdvertisingId(r7)
            boolean r8 = isAdvertisementIdValid(r7)
            if (r8 != 0) goto L24
        L22:
            r3 = r0
            goto L25
        L24:
            r3 = r7
        L25:
            com.comscore.android.id.DeviceId r1 = new com.comscore.android.id.DeviceId
            r5 = 0
            r6 = -1
            java.lang.String r2 = "googleplayapp"
            r4 = 0
            r1.<init>(r2, r3, r4, r5, r6)
            return r1
        L30:
            r7 = 0
            return r7
        L32:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "Cannot be called from the main thread"
            r7.<init>(r8)
            throw r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.comscore.android.id.IdHelperAndroid.getGooglePlayAdvertisingDeviceId(android.content.Context, boolean):com.comscore.android.id.DeviceId");
    }

    public static String getGooglePlayAdvertisingId(Context context) {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            throw new IllegalStateException("Cannot be called from the main thread");
        }
        a aVar = new a(0);
        Intent intent = new Intent(b);
        intent.setPackage(a);
        if (!context.bindService(intent, aVar, 1)) {
            return "";
        }
        try {
            return new b(aVar.a()).getId();
        } catch (Exception unused) {
            return "";
        } finally {
            context.unbindService(aVar);
        }
    }

    public static boolean isAdvertisementIdValid(String str) {
        for (String str2 : INVALID_AD_ID_VALUES) {
            if (str2.equals(str)) {
                return false;
            }
        }
        return true;
    }

    public static boolean isAdvertisingIdEnabled(Context context) {
        return isAdvertisingIdEnabled(context, false);
    }

    public static boolean isGooglePlayServicesAvailable(Context context) throws PackageManager.NameNotFoundException {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            throw new IllegalStateException("Cannot be called from the main thread");
        }
        int i = 0;
        try {
            context.getPackageManager().getPackageInfo("com.android.vending", 0);
            a aVar = new a(i);
            Intent intent = new Intent(b);
            intent.setPackage(a);
            if (context.bindService(intent, aVar, 1)) {
                context.unbindService(aVar);
                return true;
            }
        } catch (Exception unused) {
        }
        return false;
    }

    public static String md5(String str) {
        try {
            byte[] bArrDigest = MessageDigest.getInstance("MD5").digest(str.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(bArrDigest.length * 2);
            for (byte b2 : bArrDigest) {
                int i = b2 & 255;
                if (i < 16) {
                    sb.append('0');
                }
                sb.append(Integer.toHexString(i));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Huh, MD5 should be supported?", e);
        }
    }

    public static CrossPublisherId getCrossPublisherDeviceId(Context context, boolean z) {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            throw new IllegalStateException("Cannot be called from the main thread");
        }
        if (b(context)) {
            String amazonAdvertisingId = getAmazonAdvertisingId(context, z);
            if (amazonAdvertisingId != null) {
                return new CrossPublisherId(amazonAdvertisingId, 1);
            }
        } else {
            DeviceId googlePlayAdvertisingDeviceId = getGooglePlayAdvertisingDeviceId(context, z);
            if (googlePlayAdvertisingDeviceId != null) {
                return new CrossPublisherId(googlePlayAdvertisingDeviceId.getId(), 1);
            }
        }
        return new CrossPublisherId(null, 0);
    }

    public static boolean isAdvertisingIdEnabled(Context context, boolean z) {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            throw new IllegalStateException("Cannot be called from the main thread");
        }
        boolean z2 = false;
        z2 = false;
        if (!z && c) {
            return false;
        }
        a aVar = new a(z2 ? 1 : 0);
        Intent intent = new Intent(b);
        intent.setPackage(a);
        if (context.bindService(intent, aVar, 1)) {
            try {
                z2 = !new b(aVar.a()).a(true);
            } catch (Exception unused) {
            } finally {
                context.unbindService(aVar);
            }
        }
        if (!z && !z2) {
            c = true;
        }
        return z2;
    }

    private static String a(Context context) {
        try {
            return Settings.Secure.getString(context.getContentResolver(), "advertising_id");
        } catch (Exception unused) {
            return null;
        }
    }

    private static DeviceId a() {
        return new DeviceId("random", UUID.randomUUID().toString(), 7, 2, 0);
    }
}
