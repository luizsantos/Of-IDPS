/**
 * Copyright 2010-2013, Stanford University. This file is licensed under the
 * BSD license as described in the included LICENSE.txt.
 */
package net.beaconcontroller.web.view.json;

import java.io.IOException;

import org.codehaus.jackson.JsonGenerator;
import org.codehaus.jackson.JsonProcessingException;
import org.codehaus.jackson.map.JsonSerializer;
import org.codehaus.jackson.map.SerializerProvider;
import org.openflow.util.U16;

/**
 * @author David Erickson (derickso@cs.stanford.edu)
 *
 */
public class UnsignedShortJsonSerializer extends JsonSerializer<Short> {

    @Override
    public void serialize(Short value, JsonGenerator jgen,
            SerializerProvider provider) throws IOException,
            JsonProcessingException {
        jgen.writeNumber(U16.f(value));
    }
}
