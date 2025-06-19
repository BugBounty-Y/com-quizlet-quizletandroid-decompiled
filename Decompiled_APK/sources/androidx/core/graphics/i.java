package androidx.core.graphics;

import android.content.Context;
import android.content.res.AssetManager;
import android.content.res.Resources;
import android.graphics.Typeface;
import android.graphics.fonts.FontVariationAxis;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3161h6;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3170i6;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/* loaded from: classes.dex */
public class i extends AbstractC3161h6 {
    public static Class h = null;
    public static Constructor i = null;
    public static Method j = null;
    public static Method k = null;
    public static boolean l = false;
    public final Class a;
    public final Constructor b;
    public final Method c;
    public final Method d;
    public final Method e;
    public final Method f;
    public final Method g;

    public i() throws NoSuchMethodException, ClassNotFoundException, SecurityException {
        Method methodR;
        Constructor<?> constructor;
        Method methodQ;
        Method method;
        Method method2;
        Method method3;
        Class<?> cls = null;
        try {
            Class<?> cls2 = Class.forName("android.graphics.FontFamily");
            constructor = cls2.getConstructor(null);
            methodQ = q(cls2);
            Class cls3 = Integer.TYPE;
            method = cls2.getMethod("addFontFromBuffer", ByteBuffer.class, cls3, FontVariationAxis[].class, cls3, cls3);
            method2 = cls2.getMethod("freeze", null);
            method3 = cls2.getMethod("abortCreation", null);
            methodR = r(cls2);
            cls = cls2;
        } catch (ClassNotFoundException | NoSuchMethodException e) {
            Log.e("TypefaceCompatApi26Impl", "Unable to collect necessary methods for class ".concat(e.getClass().getName()), e);
            methodR = null;
            constructor = null;
            methodQ = null;
            method = null;
            method2 = null;
            method3 = null;
        }
        this.a = cls;
        this.b = constructor;
        this.c = methodQ;
        this.d = method;
        this.e = method2;
        this.f = method3;
        this.g = methodR;
    }

    public static boolean l(Object obj, String str, int i2, boolean z) throws NoSuchMethodException, ClassNotFoundException, SecurityException {
        o();
        try {
            return ((Boolean) j.invoke(obj, str, Integer.valueOf(i2), Boolean.valueOf(z))).booleanValue();
        } catch (IllegalAccessException | InvocationTargetException e) {
            throw new RuntimeException(e);
        }
    }

    public static void o() throws NoSuchMethodException, ClassNotFoundException, SecurityException {
        Method method;
        Class<?> cls;
        Method method2;
        if (l) {
            return;
        }
        l = true;
        Constructor<?> constructor = null;
        try {
            cls = Class.forName("android.graphics.FontFamily");
            Constructor<?> constructor2 = cls.getConstructor(null);
            method2 = cls.getMethod("addFontWeightStyle", String.class, Integer.TYPE, Boolean.TYPE);
            method = Typeface.class.getMethod("createFromFamiliesWithDefault", Array.newInstance(cls, 1).getClass());
            constructor = constructor2;
        } catch (ClassNotFoundException | NoSuchMethodException e) {
            Log.e("TypefaceCompatApi21Impl", e.getClass().getName(), e);
            method = null;
            cls = null;
            method2 = null;
        }
        i = constructor;
        h = cls;
        j = method2;
        k = method;
    }

    public static Method q(Class cls) {
        Class cls2 = Integer.TYPE;
        return cls.getMethod("addFontFromAssetManager", AssetManager.class, String.class, cls2, Boolean.TYPE, cls2, cls2, cls2, FontVariationAxis[].class);
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3161h6
    public final Typeface b(Context context, androidx.core.content.res.e eVar, Resources resources, int i2) throws IllegalAccessException, NoSuchMethodException, InstantiationException, ClassNotFoundException, SecurityException, ArrayIndexOutOfBoundsException, IllegalArgumentException, InvocationTargetException, NegativeArraySizeException {
        Method method = this.c;
        if (method == null) {
            Log.w("TypefaceCompatApi26Impl", "Unable to collect necessary private methods. Fallback to legacy implementation.");
        }
        if (method != null) {
            Object objP = p();
            if (objP != null) {
                androidx.core.content.res.f[] fVarArr = eVar.a;
                int length = fVarArr.length;
                int i3 = 0;
                while (i3 < length) {
                    androidx.core.content.res.f fVar = fVarArr[i3];
                    Context context2 = context;
                    if (!k(context2, objP, fVar.a, fVar.e, fVar.b, fVar.c ? 1 : 0, FontVariationAxis.fromFontVariationSettings(fVar.d))) {
                        j(objP);
                        return null;
                    }
                    i3++;
                    context = context2;
                }
                if (n(objP)) {
                    return m(objP);
                }
            }
            return null;
        }
        o();
        try {
            Object objNewInstance = i.newInstance(null);
            for (androidx.core.content.res.f fVar2 : eVar.a) {
                File fileH = AbstractC3170i6.h(context);
                if (fileH == null) {
                    return null;
                }
                try {
                } catch (RuntimeException unused) {
                } catch (Throwable th) {
                    fileH.delete();
                    throw th;
                }
                if (!AbstractC3170i6.e(fileH, resources, fVar2.f) || !l(objNewInstance, fileH.getPath(), fVar2.b, fVar2.c)) {
                    fileH.delete();
                    return null;
                }
                fileH.delete();
            }
            o();
            try {
                Object objNewInstance2 = Array.newInstance((Class<?>) h, 1);
                Array.set(objNewInstance2, 0, objNewInstance);
                return (Typeface) k.invoke(null, objNewInstance2);
            } catch (IllegalAccessException | InvocationTargetException e) {
                throw new RuntimeException(e);
            }
        } catch (IllegalAccessException | InstantiationException | InvocationTargetException e2) {
            throw new RuntimeException(e2);
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3161h6
    public final Typeface c(Context context, androidx.core.provider.h[] hVarArr, int i2) throws IllegalAccessException, IOException, IllegalArgumentException, InvocationTargetException {
        Typeface typefaceM;
        boolean zBooleanValue;
        if (hVarArr.length >= 1) {
            Method method = this.c;
            if (method == null) {
                Log.w("TypefaceCompatApi26Impl", "Unable to collect necessary private methods. Fallback to legacy implementation.");
            }
            if (method != null) {
                HashMap map = new HashMap();
                for (androidx.core.provider.h hVar : hVarArr) {
                    if (hVar.e == 0) {
                        Uri uri = hVar.a;
                        if (!map.containsKey(uri)) {
                            map.put(uri, AbstractC3170i6.j(context, uri));
                        }
                    }
                }
                Map mapUnmodifiableMap = Collections.unmodifiableMap(map);
                Object objP = p();
                if (objP != null) {
                    int length = hVarArr.length;
                    int i3 = 0;
                    boolean z = false;
                    while (i3 < length) {
                        androidx.core.provider.h hVar2 = hVarArr[i3];
                        ByteBuffer byteBuffer = (ByteBuffer) mapUnmodifiableMap.get(hVar2.a);
                        if (byteBuffer != null) {
                            try {
                                zBooleanValue = ((Boolean) this.d.invoke(objP, byteBuffer, Integer.valueOf(hVar2.b), null, Integer.valueOf(hVar2.c), Integer.valueOf(hVar2.d ? 1 : 0))).booleanValue();
                            } catch (IllegalAccessException | InvocationTargetException unused) {
                                zBooleanValue = false;
                            }
                            if (!zBooleanValue) {
                                j(objP);
                                return null;
                            }
                            z = true;
                        }
                        i3++;
                        z = z;
                    }
                    if (!z) {
                        j(objP);
                        return null;
                    }
                    if (n(objP) && (typefaceM = m(objP)) != null) {
                        return Typeface.create(typefaceM, i2);
                    }
                }
            } else {
                androidx.core.provider.h hVarF = f(hVarArr, i2);
                try {
                    ParcelFileDescriptor parcelFileDescriptorOpenFileDescriptor = context.getContentResolver().openFileDescriptor(hVarF.a, "r", null);
                    if (parcelFileDescriptorOpenFileDescriptor != null) {
                        try {
                            Typeface typefaceBuild = new Typeface.Builder(parcelFileDescriptorOpenFileDescriptor.getFileDescriptor()).setWeight(hVarF.c).setItalic(hVarF.d).build();
                            parcelFileDescriptorOpenFileDescriptor.close();
                            return typefaceBuild;
                        } finally {
                        }
                    }
                    if (parcelFileDescriptorOpenFileDescriptor != null) {
                        parcelFileDescriptorOpenFileDescriptor.close();
                        return null;
                    }
                } catch (IOException unused2) {
                }
            }
        }
        return null;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3161h6
    public final Typeface e(Context context, Resources resources, int i2, String str, int i3) throws IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        Method method = this.c;
        if (method == null) {
            Log.w("TypefaceCompatApi26Impl", "Unable to collect necessary private methods. Fallback to legacy implementation.");
        }
        if (method == null) {
            return super.e(context, resources, i2, str, i3);
        }
        Object objP = p();
        if (objP != null) {
            if (!k(context, objP, str, 0, -1, -1, null)) {
                j(objP);
                return null;
            }
            if (n(objP)) {
                return m(objP);
            }
        }
        return null;
    }

    public final void j(Object obj) throws IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        try {
            this.f.invoke(obj, null);
        } catch (IllegalAccessException | InvocationTargetException unused) {
        }
    }

    public final boolean k(Context context, Object obj, String str, int i2, int i3, int i4, FontVariationAxis[] fontVariationAxisArr) {
        try {
            return ((Boolean) this.c.invoke(obj, context.getAssets(), str, 0, Boolean.FALSE, Integer.valueOf(i2), Integer.valueOf(i3), Integer.valueOf(i4), fontVariationAxisArr)).booleanValue();
        } catch (IllegalAccessException | InvocationTargetException unused) {
            return false;
        }
    }

    public Typeface m(Object obj) throws ArrayIndexOutOfBoundsException, IllegalArgumentException, NegativeArraySizeException {
        try {
            Object objNewInstance = Array.newInstance((Class<?>) this.a, 1);
            Array.set(objNewInstance, 0, obj);
            return (Typeface) this.g.invoke(null, objNewInstance, -1, -1);
        } catch (IllegalAccessException | InvocationTargetException unused) {
            return null;
        }
    }

    public final boolean n(Object obj) {
        try {
            return ((Boolean) this.e.invoke(obj, null)).booleanValue();
        } catch (IllegalAccessException | InvocationTargetException unused) {
            return false;
        }
    }

    public final Object p() {
        try {
            return this.b.newInstance(null);
        } catch (IllegalAccessException | InstantiationException | InvocationTargetException unused) {
            return null;
        }
    }

    public Method r(Class cls) throws NoSuchMethodException, SecurityException {
        Class<?> cls2 = Array.newInstance((Class<?>) cls, 1).getClass();
        Class cls3 = Integer.TYPE;
        Method declaredMethod = Typeface.class.getDeclaredMethod("createFromFamiliesWithDefault", cls2, cls3, cls3);
        declaredMethod.setAccessible(true);
        return declaredMethod;
    }
}
