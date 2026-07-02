import { StatusBar } from 'expo-status-bar';
import { StyleSheet, Text, View } from 'react-native';

export default function App() {
  return (
    <View style={styles.container}>
      <Text style={styles.title}>Signet</Text>
      <Text style={styles.subtitle}>
        Example app for the react-native-signet binding.
      </Text>
      <StatusBar style="auto" />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#fff',
    alignItems: 'center',
    justifyContent: 'center',
    padding: 24,
  },
  title: {
    color: '#000',
    fontSize: 28,
    fontWeight: '600',
  },
  subtitle: {
    color: '#444',
    marginTop: 8,
    textAlign: 'center',
  },
});
