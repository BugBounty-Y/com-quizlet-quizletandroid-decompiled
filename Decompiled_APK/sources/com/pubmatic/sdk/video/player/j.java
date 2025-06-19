package com.pubmatic.sdk.video.player;

import androidx.annotation.NonNull;
import com.pubmatic.sdk.video.vastmodels.l;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;

/* loaded from: classes2.dex */
public class j {

    @NonNull
    private SortedMap<Integer, Map<l.b, List<String>>> a = new TreeMap();

    @NonNull
    private k b;

    public j(@NonNull k kVar) {
        this.b = kVar;
    }

    public void addProgressUrls(@NonNull Integer num, l.b bVar, @NonNull List<String> list) {
        Map<l.b, List<String>> map = this.a.get(num);
        if (map == null) {
            HashMap map2 = new HashMap();
            map2.put(bVar, list);
            this.a.put(num, map2);
        } else {
            List<String> list2 = map.get(bVar);
            if (list2 == null) {
                map.put(bVar, list);
            } else {
                list2.addAll(list);
            }
        }
    }

    public void onProgress(int i) {
        Map<l.b, List<String>> map;
        if (this.a.isEmpty()) {
            return;
        }
        Integer numFirstKey = this.a.firstKey();
        if (i < numFirstKey.intValue() || (map = this.a.get(numFirstKey)) == null) {
            return;
        }
        this.b.onProgressReached(map);
        this.a.remove(numFirstKey);
    }
}
