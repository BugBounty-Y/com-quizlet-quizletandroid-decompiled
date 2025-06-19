package androidx.media;

import androidx.versionedparcelable.a;
import androidx.versionedparcelable.c;
import java.lang.reflect.InvocationTargetException;

/* loaded from: classes.dex */
public class AudioAttributesCompatParcelizer {
    public static AudioAttributesCompat read(a aVar) {
        AudioAttributesCompat audioAttributesCompat = new AudioAttributesCompat();
        c cVarH = audioAttributesCompat.a;
        if (aVar.e(1)) {
            cVarH = aVar.h();
        }
        audioAttributesCompat.a = (AudioAttributesImpl) cVarH;
        return audioAttributesCompat;
    }

    public static void write(AudioAttributesCompat audioAttributesCompat, a aVar) throws IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        aVar.getClass();
        AudioAttributesImpl audioAttributesImpl = audioAttributesCompat.a;
        aVar.i(1);
        aVar.l(audioAttributesImpl);
    }
}
