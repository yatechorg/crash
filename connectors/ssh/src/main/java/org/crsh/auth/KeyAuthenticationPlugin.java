/*
 * Copyright (C) 2012 eXo Platform SAS.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.crsh.auth;

import org.apache.sshd.common.KeyPairProvider;
import org.crsh.plugin.CRaSHPlugin;
import org.crsh.plugin.PropertyDescriptor;

import java.io.File;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;

/** @author <a href="mailto:julien.viet@exoplatform.com">Julien Viet</a> */
public class KeyAuthenticationPlugin extends CRaSHPlugin<KeyAuthenticationPlugin> implements AuthenticationPlugin<PublicKey> {

  /** . */
  private static final String[] TYPES = { KeyPairProvider.SSH_DSS, KeyPairProvider.SSH_RSA };

  /** The SSH authorized key path. */
  public static final PropertyDescriptor<String> AUTHORIZED_KEY_PATH = PropertyDescriptor.create(
      "auth.key.path",
      (String)null,
      "The path to the authorized key file");

  /** . */
  private Set<PublicKey> authorizedKeys = Collections.emptySet();

  @Override
  protected Iterable<PropertyDescriptor<?>> createConfigurationCapabilities() {
    return Arrays.<PropertyDescriptor<?>>asList(AUTHORIZED_KEY_PATH);
  }

  public String getName() {
    return "key";
  }

  @Override
  public KeyAuthenticationPlugin getImplementation() {
    return this;
  }

  public Class<PublicKey> getCredentialType() {
    return PublicKey.class;
  }

  @Override
  public void init() {
    loadAuthorizedKeys();
  }

  /**
   * Reload the authorized keys from the path defined by the "auth.key.path" property
   */
  public void reloadAuthorizedKeys() {
    authorizedKeys = Collections.emptySet();
    loadAuthorizedKeys();
  }

  private void loadAuthorizedKeys() {
    String[] authorizedKeyPaths = collectAuthorizedKeyPaths();
    if (authorizedKeyPaths.length > 0) {
      Set<PublicKey> keys;
      keys = new LinkedHashSet<PublicKey>();
      KeyPairProvider provider = new FilePublicKeyProvider(authorizedKeyPaths);
      for (String type : TYPES) {
        KeyPair pair = provider.loadKey(type);
        if (pair != null) {
          PublicKey key = pair.getPublic();
          if (key != null) {
            keys.add(key);
          }
        }
      }
      authorizedKeys = keys;
    }
  }

  /**
   * Collect the authorized key paths according to the auth.key.path property defined.
   * If the path is a file - it is used. If it is a directory, it is scanned for files (shallow scan, not recursive)
   * @return an array of the collected paths (never <code>null</code>).
   */
  private String[] collectAuthorizedKeyPaths() {
    List<String> paths = new LinkedList<String>();
    String authorizedKeyPath = getContext().getProperty(AUTHORIZED_KEY_PATH);
    if (authorizedKeyPath != null) {
      File f = new File(authorizedKeyPath);
      if (f.exists()) {
        log.log(Level.FINE, "Found authorized key path " + authorizedKeyPath);
        if (f.isFile()) {
          paths.add(authorizedKeyPath);
        } else if (f.isDirectory()) {
          log.log(Level.FINE, "Collecting authorized key paths from directory " + authorizedKeyPath);
          for (File child : f.listFiles()) {
            if (child.isFile()) {
              log.log(Level.FINE, "Adding authorized key path " + child.getPath());
              paths.add(child.getPath());
            }
          }
        }
      } else {
        log.log(Level.FINE, "Ignoring invalid authorized key path " + authorizedKeyPath);
      }
    }
    return paths.toArray(new String[paths.size()]);
  }

  public boolean authenticate(String username, PublicKey credential) throws Exception {
    if (authorizedKeys.contains(credential)) {
      log.log(Level.FINE, "Authenticated " + username + " with public key " + credential);
      return true;
    } else {
      log.log(Level.FINE, "Denied " + username + " with public key " + credential);
      return false;
    }
  }
}
