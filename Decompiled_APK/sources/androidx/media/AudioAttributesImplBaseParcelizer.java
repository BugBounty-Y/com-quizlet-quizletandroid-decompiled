package androidx.media;

import androidx.versionedparcelable.a;

/* loaded from: classes.dex */
public class AudioAttributesImplBaseParcelizer {
    public static AudioAttributesImplBase read(a aVar) {
        AudioAttributesImplBase audioAttributesImplBase = new AudioAttributesImplBase();
        audioAttributesImplBase.a = aVar.f(audioAttributesImplBase.a, 1);
        audioAttributesImplBase.b = aVar.f(audioAttributesImplBase.b, 2);
        audioAttributesImplBase.c = aVar.f(audioAttributesImplBase.c, 3);
        audioAttributesImplBase.d = aVar.f(audioAttributesImplBase.d, 4);
        return audioAttributesImplBase;
    }

    public static void write(AudioAttributesImplBase audioAttributesImplBase, a aVar) {
        aVar.getClass();
        aVar.j(audioAttributesImplBase.a, 1);
        aVar.j(audioAttributesImplBase.b, 2);
        aVar.j(audioAttributesImplBase.c, 3);
        aVar.j(audioAttributesImplBase.d, 4);
    }
}
