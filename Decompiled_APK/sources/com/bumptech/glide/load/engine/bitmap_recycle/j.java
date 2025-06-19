package com.bumptech.glide.load.engine.bitmap_recycle;

import android.graphics.Bitmap;
import androidx.compose.animation.d0;
import com.bumptech.glide.util.m;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.NavigableMap;
import java.util.TreeMap;

/* loaded from: classes.dex */
public final class j {
    public static final Bitmap.Config[] d;
    public static final Bitmap.Config[] e;
    public static final Bitmap.Config[] f;
    public static final Bitmap.Config[] g;
    public static final Bitmap.Config[] h;
    public final e a = new e(1);
    public final com.quizlet.data.repository.activitycenter.b b = new com.quizlet.data.repository.activitycenter.b(7);
    public final HashMap c = new HashMap();

    static {
        Bitmap.Config[] configArr = (Bitmap.Config[]) Arrays.copyOf(new Bitmap.Config[]{Bitmap.Config.ARGB_8888, null}, 3);
        configArr[configArr.length - 1] = Bitmap.Config.RGBA_F16;
        d = configArr;
        e = configArr;
        f = new Bitmap.Config[]{Bitmap.Config.RGB_565};
        g = new Bitmap.Config[]{Bitmap.Config.ARGB_4444};
        h = new Bitmap.Config[]{Bitmap.Config.ALPHA_8};
    }

    public static String c(int i, Bitmap.Config config) {
        return "[" + i + "](" + config + ")";
    }

    public final void a(Integer num, Bitmap bitmap) {
        NavigableMap navigableMapD = d(bitmap.getConfig());
        Integer num2 = (Integer) navigableMapD.get(num);
        if (num2 != null) {
            if (num2.intValue() == 1) {
                navigableMapD.remove(num);
                return;
            } else {
                navigableMapD.put(num, Integer.valueOf(num2.intValue() - 1));
                return;
            }
        }
        throw new NullPointerException("Tried to decrement empty size, size: " + num + ", removed: " + c(m.c(bitmap), bitmap.getConfig()) + ", this: " + this);
    }

    public final Bitmap b(int i, int i2, Bitmap.Config config) {
        Bitmap.Config[] configArr;
        int iD = m.d(config) * i * i2;
        e eVar = this.a;
        g gVarT = (g) ((ArrayDeque) eVar.b).poll();
        if (gVarT == null) {
            gVarT = eVar.T();
        }
        i iVar = (i) gVarT;
        iVar.b = iD;
        iVar.c = config;
        if (Bitmap.Config.RGBA_F16.equals(config)) {
            configArr = e;
        } else {
            int i3 = h.a[config.ordinal()];
            configArr = i3 != 1 ? i3 != 2 ? i3 != 3 ? i3 != 4 ? new Bitmap.Config[]{config} : h : g : f : d;
        }
        int length = configArr.length;
        int i4 = 0;
        while (true) {
            if (i4 >= length) {
                break;
            }
            Bitmap.Config config2 = configArr[i4];
            Integer num = (Integer) d(config2).ceilingKey(Integer.valueOf(iD));
            if (num == null || num.intValue() > iD * 8) {
                i4++;
            } else if (num.intValue() != iD || (config2 != null ? !config2.equals(config) : config != null)) {
                eVar.J(iVar);
                int iIntValue = num.intValue();
                g gVarT2 = (g) ((ArrayDeque) eVar.b).poll();
                if (gVarT2 == null) {
                    gVarT2 = eVar.T();
                }
                iVar = (i) gVarT2;
                iVar.b = iIntValue;
                iVar.c = config2;
            }
        }
        Bitmap bitmap = (Bitmap) this.b.h(iVar);
        if (bitmap != null) {
            a(Integer.valueOf(iVar.b), bitmap);
            bitmap.reconfigure(i, i2, config);
        }
        return bitmap;
    }

    public final NavigableMap d(Bitmap.Config config) {
        HashMap map = this.c;
        NavigableMap navigableMap = (NavigableMap) map.get(config);
        if (navigableMap != null) {
            return navigableMap;
        }
        TreeMap treeMap = new TreeMap();
        map.put(config, treeMap);
        return treeMap;
    }

    public final void e(Bitmap bitmap) {
        int iC = m.c(bitmap);
        Bitmap.Config config = bitmap.getConfig();
        e eVar = this.a;
        g gVarT = (g) ((ArrayDeque) eVar.b).poll();
        if (gVarT == null) {
            gVarT = eVar.T();
        }
        i iVar = (i) gVarT;
        iVar.b = iC;
        iVar.c = config;
        this.b.m(iVar, bitmap);
        NavigableMap navigableMapD = d(bitmap.getConfig());
        Integer num = (Integer) navigableMapD.get(Integer.valueOf(iVar.b));
        navigableMapD.put(Integer.valueOf(iVar.b), Integer.valueOf(num != null ? 1 + num.intValue() : 1));
    }

    public final String toString() {
        StringBuilder sbU = d0.u("SizeConfigStrategy{groupedMap=");
        sbU.append(this.b);
        sbU.append(", sortedSizes=(");
        HashMap map = this.c;
        for (Map.Entry entry : map.entrySet()) {
            sbU.append(entry.getKey());
            sbU.append('[');
            sbU.append(entry.getValue());
            sbU.append("], ");
        }
        if (!map.isEmpty()) {
            sbU.replace(sbU.length() - 2, sbU.length(), "");
        }
        sbU.append(")}");
        return sbU.toString();
    }
}
